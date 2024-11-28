# social_media.py

import requests
import logging

logger = logging.getLogger(__name__)

def social_media_lookup(email):
    """Look for potential social media accounts using email username."""
    username = email.split('@')[0]  # Extract username from email

    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "YouTube": f"https://www.youtube.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Medium": f"https://medium.com/@{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Quora": f"https://www.quora.com/profile/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "StackOverflow": f"https://stackoverflow.com/users/{username}",
        "Kaggle": f"https://www.kaggle.com/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "WeHeartIt": f"https://weheartit.com/{username}",
        "Wattpad": f"https://www.wattpad.com/user/{username}",
        "Strava": f"https://www.strava.com/athletes/{username}",
        "Bandcamp": f"https://bandcamp.com/{username}",
    }

    found_accounts = {}
    failed_checks = []

    for platform, url in platforms.items():
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                found_accounts[platform] = url
                logger.info(f"✅ Account found on {platform}: {url}")
            else:
                logger.info(f"❌ No account found on {platform}.")
        except requests.exceptions.RequestException:
            failed_checks.append(platform)
            logger.warning(f"⚠️ Error checking {platform}.")
    
    return {"Found Accounts": found_accounts, "Failed Checks": failed_checks}
