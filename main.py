# main.py
# Entry point for the Ransomware Detection System.
# Configures logging, optional CLI flags, and launches the GUI.
#
# Usage:
#   python main.py                          # Launch GUI (default)
#   python main.py --industry healthcare    # Pre-select industry on startup
#   python main.py --ioc /path/custom.json  # Load custom IOC feed on startup

import argparse
import logging
import os
import sys

# Configure structured logging to both console and log file
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(LOG_DIR, "system.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ransomware Detection System — Multi-Industry Cybersecurity Platform"
    )
    parser.add_argument(
        "--industry",
        default="general",
        choices=["healthcare", "banking", "nuclear", "energy", "government", "general"],
        help="Industry profile to activate on startup (default: general)"
    )
    parser.add_argument(
        "--ioc",
        default=None,
        metavar="PATH",
        help="Path to a custom IOC JSON feed file to load on startup"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Pre-configure the ThreatIntelligenceEngine before launching the GUI
    from threat_intelligence import reset_engine
    engine = reset_engine(industry=args.industry, custom_ioc_file=args.ioc)
    logger.info(
        "Starting Ransomware Detection System | industry='%s' | custom_ioc='%s'",
        args.industry, args.ioc or "none"
    )

    from application import start_gui
    start_gui()
