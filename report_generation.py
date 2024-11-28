import logging
from transformers import pipeline

# Module-specific logger
logger = logging.getLogger(__name__)

def generate_detailed_report(details, ai_summary):
    """
    Generate a detailed descriptive report based on the OSINT findings.
    
    Args:
        details (dict): The OSINT analysis results.
        ai_summary (str): AI-generated summary of the analysis.

    Returns:
        str: A detailed report summarizing the findings.
    """
    logger.info("Generating detailed report...")
    
    # Load summarizer
    try:
        summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
        logger.info("AI summarizer model loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load AI summarizer: {e}")
        return "AI summarization unavailable due to an error."

    # Prepare the text input for summarization
    report_text_lines = []
    for key, value in details.items():
        if isinstance(value, dict):
            report_text_lines.append(f"{key}:\n")
            for subkey, subvalue in value.items():
                report_text_lines.append(f"  - {subkey}: {subvalue}\n")
        else:
            report_text_lines.append(f"{key}: {value}\n")
    report_text = "".join(report_text_lines)

    # Generate the descriptive report
    try:
        logger.info("Splitting input text into manageable chunks for summarization...")
        chunks = [report_text[i:i + 1024] for i in range(0, len(report_text), 1024)]
        if not chunks:
            raise ValueError("Report text is empty or too small for summarization.")
        
        detailed_report_lines = []
        for i, chunk in enumerate(chunks, 1):
            logger.info(f"Processing chunk {i}/{len(chunks)}...")
            summary = summarizer(chunk, max_length=300, min_length=100, do_sample=False)
            detailed_report_lines.append(summary[0]["summary_text"] + "\n")
        
        # Combine the summaries and append the AI Summary
        detailed_report = "".join(detailed_report_lines)
        detailed_report += "\nAI Summary:\n" + ai_summary

        logger.info("Detailed report generated successfully.")
        return detailed_report.strip()
    except Exception as e:
        logger.error(f"Failed to generate detailed report: {e}")
        return "AI detailed report generation failed due to an error."
