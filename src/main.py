import argparse
import logging
from src.capture.packet_sniffer import start_sniffing
from src.preprocess import preprocess_data
from src.detection.threshold_detection import threshold_detection
from src.detection.ml_detection import train_model, predict_anomaly
from src.filtering.ip_filter import check_and_filter_ip
from src.visualize import visualize_data
from src.utils.config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, filename=Config.LOG_PATH,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def setup_arg_parser():
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(description="DDoS Detection Tool")
    parser.add_argument('--sniff_count', type=int, default=50, help='Number of packets to sniff')
    parser.add_argument('--threshold', type=int, help='Set custom packet rate threshold')
    return parser

def main(sniff_count):
    # Load and validate configuration
    config = Config(config_file="../config/config.json")
    config.validate()

    # Phase 1: Start packet sniffing
    logging.info("Starting packet sniffing...")
    start_sniffing(count=sniff_count)

    # Phase 2: Preprocess data
    logging.info("Preprocessing data...")
    preprocess_data(file_path=config.config["RAW_DATA_PATH"])

    # Phase 3: Train the ML model
    logging.info("Training ML model...")
    train_model(file_path=config.config["PROCESSED_DATA_PATH"])

    # Phase 4: Predict anomalies
    logging.info("Predicting anomalies...")
    anomalies = predict_anomaly(model_path=config.config["MODEL_PATH"], 
                                 data_path=config.config["PROCESSED_DATA_PATH"])

    # Phase 5: Check and filter IPs
    logging.info("Checking and filtering IPs...")
    packet_rate = 120  # Example packet rate from analysis
    src_ip = "192.168.1.1"  # Example source IP
    if check_and_filter_ip(src_ip):
        logging.warning(f"{src_ip} has been blacklisted.")
    
    # Additional threshold check
    if config.config["THRESHOLD_PACKET_RATE"] and packet_rate > config.config["THRESHOLD_PACKET_RATE"]:
        threshold_detection(packet_rate, src_ip)

    # Phase 6: Visualize the results
    logging.info("Visualizing results...")
    visualize_data(file_path=config.config["ANOMALY_DATA_PATH"])

if __name__ == "__main__":
    arg_parser = setup_arg_parser()
    args = arg_parser.parse_args()
    
    try:
        main(sniff_count=args.sniff_count)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
