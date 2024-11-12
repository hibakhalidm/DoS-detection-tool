# src/detection/ml_detection.py
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

def load_processed_data(file_path):
    """Load processed data for training."""
    return pd.read_csv(file_path)

def train_model(file_path):
    """Train an ensemble model using Random Forest and Isolation Forest."""
    # Load the processed data
    data = load_processed_data(file_path)

    # Define features and target
    features = data.drop(columns=['timestamp', 'src_ip', 'dst_ip', 'flags', 'is_syn'])
    target = data['is_syn']  # Assuming 'is_syn' is the target for DDoS detection

    # Normalize features
    scaler = StandardScaler()
    features = scaler.fit_transform(features)

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2, random_state=42)

    # Train a Random Forest model
    rf_model = RandomForestClassifier(random_state=42)
    
    # Hyperparameter tuning with GridSearchCV
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10]
    }

    grid_search = GridSearchCV(estimator=rf_model, param_grid=param_grid, cv=3, scoring='f1')
    grid_search.fit(X_train, y_train)

    # Best model
    best_rf_model = grid_search.best_estimator_

    # Save the trained model
    with open('../models/trained_rf_model.pkl', 'wb') as model_file:
        pickle.dump(best_rf_model, model_file)

    print("Random Forest model trained and saved.")

    # Train Isolation Forest for anomaly detection
    iso_model = IsolationForest(contamination=0.01)
    iso_model.fit(X_train)

    # Save the Isolation Forest model
    with open('../models/trained_iso_model.pkl', 'wb') as model_file:
        pickle.dump(iso_model, model_file)

    print("Isolation Forest model trained and saved.")

    # Evaluate the Random Forest model
    y_pred_rf = best_rf_model.predict(X_test)
    print("\nRandom Forest Classification Report:")
    print(classification_report(y_test, y_pred_rf))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_rf))

def predict_anomaly(model_path, data_path):
    """Predict anomalies using the trained models."""
    # Load processed data
    data = load_processed_data(data_path)

    # Define features
    features = data.drop(columns=['timestamp', 'src_ip', 'dst_ip', 'flags', 'is_syn'])
    scaler = StandardScaler()
    features = scaler.fit_transform(features)

    # Load the Random Forest model
    with open(model_path, 'rb') as model_file:
        rf_model = pickle.load(model_file)

    # Predict using Random Forest
    predictions_rf = rf_model.predict(features)
    data['rf_prediction'] = predictions_rf

    # Load the Isolation Forest model
    with open('../models/trained_iso_model.pkl', 'rb') as model_file:
        iso_model = pickle.load(model_file)

    # Predict using Isolation Forest
    predictions_iso = iso_model.predict(features)
    data['iso_prediction'] = ['Anomaly' if x == -1 else 'Normal' for x in predictions_iso]

    # Save the results
    data.to_csv('../data/processed/anomaly_detected.csv', index=False)
    print("Anomaly detection results saved to anomaly_detected.csv")

if __name__ == "__main__":
    # You can call the functions here to train and predict anomalies
    train_model("../data/processed/processed_data.csv")
    predict_anomaly("../models/trained_rf_model.pkl", "../data/processed/processed_data.csv")
