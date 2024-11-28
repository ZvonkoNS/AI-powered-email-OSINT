import logging
from transformers import pipeline
import os

# Module-specific logger
logger = logging.getLogger(__name__)

def summarize_with_chunks(text, max_length=512, chunk_overlap=100, model_name=None):
    """
    Generate a summary for the given text using AI summarization.
    
    Args:
        text (str): The input text to summarize.
        max_length (int): Maximum length of each chunk for summarization.
        chunk_overlap (int): Number of overlapping characters between chunks for context.
        model_name (str): Optional, specify the summarization model to use.

    Returns:
        str: The AI-generated summary.
    """
    os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

    # Set default model if not provided
    model_name = model_name or os.getenv("SUMMARIZATION_MODEL", "facebook/bart-large-cnn")

    # Load summarization model
    try:
        logger.info(f"Loading summarization model: {model_name}...")
        summarizer = pipeline("summarization", model=model_name)
        logger.info(f"Summarization model '{model_name}' loaded successfully.")
    except Exception as e:
        logger.error(f"Error loading summarization model '{model_name}': {e}")
        return "AI summarization unavailable due to an error."

    # Split text into manageable overlapping chunks
    chunks = []
    for i in range(0, len(text), max_length - chunk_overlap):
        chunks.append(text[i:i + max_length])

    logger.info(f"Input text split into {len(chunks)} chunks for summarization.")
    summary = []

    # Summarize each chunk
    try:
        for i, chunk in enumerate(chunks, 1):
            logger.info(f"Processing chunk {i} of {len(chunks)}...")
            # Adjust max_length and min_length dynamically
            dynamic_max_len = min(len(chunk), 200)  # Limit summarization length for smaller chunks
            dynamic_min_len = dynamic_max_len // 2

            try:
                result = summarizer(
                    chunk, 
                    max_length=dynamic_max_len, 
                    min_length=dynamic_min_len, 
                    do_sample=False
                )
                summary_text = result[0]['summary_text']
                summary.append(summary_text)
                logger.debug(f"Chunk {i} summary: {summary_text}")
            except Exception as chunk_error:
                logger.error(f"Failed to summarize chunk {i}: {chunk_error}")
                summary.append(f"[Chunk {i} summarization failed]")

        full_summary = " ".join(summary).strip()
        logger.info("AI-powered summarization complete.")
        return full_summary
    except Exception as e:
        logger.error(f"Summarization failed: {e}")
        return "AI summarization failed due to an error."
