# src/visualize.py
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import os

def visualize_data(file_path="../data/processed/anomaly_detected.csv", 
                  save_path="../data/processed/anomaly_plot.png", 
                  plot_type='line'):
    try:
        # Load data
        data = pd.read_csv(file_path)
        data['timestamp'] = pd.to_datetime(data['timestamp'])

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(12, 6))

        # Plot based on selected plot type
        if plot_type == 'line':
            ax.plot(data['timestamp'], data['pkt_size'], label="Packet Size", color='blue')
        elif plot_type == 'scatter':
            ax.scatter(data['timestamp'], data['pkt_size'], label="Packet Size", color='blue')
        else:
            raise ValueError("Unsupported plot type. Use 'line' or 'scatter'.")

        # Highlight anomalies
        ax.scatter(data[data['anomaly'] == 1]['timestamp'], 
                   data[data['anomaly'] == 1]['pkt_size'], 
                   color='red', label="Anomaly", zorder=5)

        # Set title and labels
        ax.set_xlabel("Timestamp", fontsize=12)
        ax.set_ylabel("Packet Size", fontsize=12)
        ax.set_title("Traffic and Anomalies", fontsize=16)
        ax.legend()

        # Format x-axis for better readability
        ax.xaxis.set_major_formatter(DateFormatter("%Y-%m-%d %H:%M"))
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Show the plot
        plt.show()

        # Save the plot
        if save_path:
            plt.savefig(save_path, format='png', dpi=300)
            print(f"Plot saved to {save_path}")

    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except pd.errors.EmptyDataError:
        print(f"Error: The file {file_path} is empty.")
    except ValueError as ve:
        print(f"Value Error: {ve}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    visualize_data()
