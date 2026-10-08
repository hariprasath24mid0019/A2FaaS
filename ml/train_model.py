"""
============================================================
A²FaaS
AI-Assisted Adaptive Firewall-as-a-Service

Machine Learning Training Pipeline
============================================================

Purpose
-------
Train and evaluate the A²FaaS adaptive firewall risk model
using the official UNSW-NB15 training dataset.

Machine Learning Model
----------------------
Logistic Regression

Target
------
0 = Normal traffic
1 = Attack traffic

Dataset
-------
UNSW_NB15_training-set.csv

Generated Files
---------------
1. a2faas_risk_model.joblib
2. model_metrics.json

Evaluation
----------
- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix

Data Split
----------
80% -> Training
20% -> Validation

Important
---------
The "attack_cat" column is intentionally excluded because
it directly describes the attack category and would create
target leakage if supplied to the classifier.

============================================================
"""

from pathlib import Path
import json
import time

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ML_DIR = PROJECT_ROOT / "ml"

DATASET_PATH = ML_DIR / "UNSW_NB15_training-set.csv"

MODEL_PATH = ML_DIR / "a2faas_risk_model.joblib"

METRICS_PATH = ML_DIR / "model_metrics.json"


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TEST_SIZE = 0.20

MAX_ITERATIONS = 1000


# ============================================================
# DATA LOADING
# ============================================================

def load_dataset() -> pd.DataFrame:
    """
    Load the official UNSW-NB15 training dataset.
    """

    print("=" * 72)
    print("A²FaaS ML TRAINING PIPELINE")
    print("=" * 72)

    print("\n[1/7] Loading UNSW-NB15 dataset...")

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            "\nDataset not found.\n\n"
            f"Expected location:\n{DATASET_PATH}\n\n"
            "Make sure the file is inside the ml folder."
        )

    print(
        f"Dataset path:\n{DATASET_PATH}"
    )

    dataframe = pd.read_csv(
        DATASET_PATH,
        low_memory=False,
    )

    print(
        f"\nRecords loaded : {len(dataframe):,}"
    )

    print(
        f"Columns loaded : {len(dataframe.columns)}"
    )

    return dataframe


# ============================================================
# DATA PREPARATION
# ============================================================

def prepare_dataset(
    dataframe: pd.DataFrame,
):
    """
    Prepare input features and binary target labels.
    """

    print("\n[2/7] Preparing dataset...")

    dataframe = dataframe.copy()

    # --------------------------------------------------------
    # Clean column names
    # --------------------------------------------------------

    dataframe.columns = [
        str(column).strip()
        for column in dataframe.columns
    ]

    print("\nDataset columns:")

    for column in dataframe.columns:
        print(f"  - {column}")

    # --------------------------------------------------------
    # Verify target column
    # --------------------------------------------------------

    if "label" not in dataframe.columns:
        raise ValueError(
            "The required 'label' column was not found "
            "in the dataset."
        )

    # --------------------------------------------------------
    # Remove identifier and target-leakage columns
    # --------------------------------------------------------

    columns_to_drop = []

    if "id" in dataframe.columns:
        columns_to_drop.append("id")

    if "attack_cat" in dataframe.columns:
        columns_to_drop.append("attack_cat")

    if columns_to_drop:
        print(
            "\nRemoving non-predictive / leakage columns:"
        )

        for column in columns_to_drop:
            print(f"  - {column}")

        dataframe = dataframe.drop(
            columns=columns_to_drop
        )

    # --------------------------------------------------------
    # Separate target
    # --------------------------------------------------------

    y = pd.to_numeric(
        dataframe["label"],
        errors="coerce",
    )

    X = dataframe.drop(
        columns=["label"]
    )

    # --------------------------------------------------------
    # Remove invalid target rows
    # --------------------------------------------------------

    valid_rows = y.notna()

    X = X.loc[
        valid_rows
    ].reset_index(drop=True)

    y = y.loc[
        valid_rows
    ].reset_index(drop=True)

    # --------------------------------------------------------
    # Convert target to binary classification
    #
    # 0 = Normal
    # 1 = Attack
    # --------------------------------------------------------

    y = (
        y.astype(int) > 0
    ).astype(int)

    # --------------------------------------------------------
    # Dataset summary
    # --------------------------------------------------------

    print(
        f"\nFinal samples  : {len(X):,}"
    )

    print(
        f"Final features : {X.shape[1]}"
    )

    print("\nTarget distribution:")

    target_counts = (
        y.value_counts()
        .sort_index()
    )

    normal_count = int(
        target_counts.get(0, 0)
    )

    attack_count = int(
        target_counts.get(1, 0)
    )

    print(
        f"  Normal traffic : {normal_count:,}"
    )

    print(
        f"  Attack traffic : {attack_count:,}"
    )

    return X, y


# ============================================================
# PREPROCESSING PIPELINE
# ============================================================

def build_preprocessor(
    X: pd.DataFrame,
):
    """
    Build preprocessing for numerical and categorical
    network-traffic features.

    Numerical:
        Median imputation
        Standard scaling

    Categorical:
        Most-frequent imputation
        One-hot encoding
    """

    print(
        "\n[3/7] Building preprocessing pipeline..."
    )

    numerical_columns = (
        X.select_dtypes(
            include=["number"]
        )
        .columns
        .tolist()
    )

    categorical_columns = (
        X.select_dtypes(
            exclude=["number"]
        )
        .columns
        .tolist()
    )

    print(
        f"Numerical features   : "
        f"{len(numerical_columns)}"
    )

    print(
        f"Categorical features : "
        f"{len(categorical_columns)}"
    )

    # --------------------------------------------------------
    # Numerical preprocessing
    # --------------------------------------------------------

    numerical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="median"
                ),
            ),
            (
                "scaler",
                StandardScaler(),
            ),
        ]
    )

    # --------------------------------------------------------
    # Categorical preprocessing
    # --------------------------------------------------------

    categorical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="most_frequent"
                ),
            ),
            (
                "encoder",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=True,
                ),
            ),
        ]
    )

    transformers = []

    if numerical_columns:
        transformers.append(
            (
                "numerical",
                numerical_pipeline,
                numerical_columns,
            )
        )

    if categorical_columns:
        transformers.append(
            (
                "categorical",
                categorical_pipeline,
                categorical_columns,
            )
        )

    return ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        sparse_threshold=0.3,
    )


# ============================================================
# TRAIN / VALIDATION SPLIT
# ============================================================

def split_dataset(
    X: pd.DataFrame,
    y: pd.Series,
):
    """
    Split the dataset into training and validation subsets.

    80% -> Training
    20% -> Validation

    Stratification preserves the class distribution.
    """

    print(
        "\n[4/7] Creating training/validation split..."
    )

    X_train, X_validation, y_train, y_validation = (
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        )
    )

    print(
        f"Training samples   : "
        f"{len(X_train):,}"
    )

    print(
        f"Validation samples : "
        f"{len(X_validation):,}"
    )

    print(
        "\nTraining class distribution:"
    )

    print(
        y_train.value_counts()
        .sort_index()
        .rename(
            index={
                0: "Normal",
                1: "Attack",
            }
        )
    )

    print(
        "\nValidation class distribution:"
    )

    print(
        y_validation.value_counts()
        .sort_index()
        .rename(
            index={
                0: "Normal",
                1: "Attack",
            }
        )
    )

    return (
        X_train,
        X_validation,
        y_train,
        y_validation,
    )


# ============================================================
# MODEL TRAINING
# ============================================================

def train_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
):
    """
    Train the Logistic Regression classifier.
    """

    print(
        "\n[5/7] Training Logistic Regression model..."
    )

    preprocessor = build_preprocessor(
        X_train
    )

    classifier = LogisticRegression(
        max_iter=MAX_ITERATIONS,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )

    model_pipeline = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "classifier",
                classifier,
            ),
        ]
    )

    print(
        "\nStarting model training..."
    )

    training_start = time.perf_counter()

    model_pipeline.fit(
        X_train,
        y_train,
    )

    training_time = (
        time.perf_counter()
        - training_start
    )

    print(
        "\nModel training completed."
    )

    print(
        f"Training time : "
        f"{training_time:.2f} seconds"
    )

    return (
        model_pipeline,
        training_time,
    )


# ============================================================
# MODEL EVALUATION
# ============================================================

def evaluate_model(
    model,
    X_validation: pd.DataFrame,
    y_validation: pd.Series,
):
    """
    Evaluate the trained model on unseen validation data.
    """

    print(
        "\n[6/7] Evaluating model..."
    )

    prediction_start = time.perf_counter()

    predictions = model.predict(
        X_validation
    )

    prediction_time = (
        time.perf_counter()
        - prediction_start
    )

    # --------------------------------------------------------
    # Classification metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_validation,
        predictions,
    )

    precision = precision_score(
        y_validation,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_validation,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_validation,
        predictions,
        zero_division=0,
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    matrix = confusion_matrix(
        y_validation,
        predictions,
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    report = classification_report(
        y_validation,
        predictions,
        target_names=[
            "Normal",
            "Attack",
        ],
        zero_division=0,
    )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print("\n" + "=" * 72)
    print("A²FaaS ML MODEL PERFORMANCE")
    print("=" * 72)

    print(
        f"\nAccuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print(
        f"Prediction time : "
        f"{prediction_time:.4f} seconds"
    )

    print(
        "\nClassification Report:"
    )

    print(
        report
    )

    print(
        "Confusion Matrix:"
    )

    print(
        matrix
    )

    # --------------------------------------------------------
    # Calculate average prediction latency
    # --------------------------------------------------------

    validation_count = len(
        X_validation
    )

    if validation_count > 0:
        average_prediction_ms = (
            prediction_time
            / validation_count
        ) * 1000
    else:
        average_prediction_ms = 0.0

    # --------------------------------------------------------
    # Build metrics dictionary
    # --------------------------------------------------------

    metrics = {
        "model": "LogisticRegression",
        "dataset": (
            "UNSW_NB15_training-set.csv"
        ),
        "random_state": RANDOM_STATE,
        "validation_split": TEST_SIZE,
        "samples": int(
            validation_count
        ),
        "accuracy": float(
            accuracy
        ),
        "precision": float(
            precision
        ),
        "recall": float(
            recall
        ),
        "f1_score": float(
            f1
        ),
        "prediction_time_seconds": float(
            prediction_time
        ),
        "average_prediction_latency_ms": float(
            average_prediction_ms
        ),
        "confusion_matrix": (
            matrix.tolist()
        ),
    }

    return metrics


# ============================================================
# SAVE TRAINED MODEL
# ============================================================

def save_model(
    model,
):
    """
    Save the complete preprocessing + model pipeline.
    """

    print(
        "\nSaving trained model..."
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    print(
        f"Model saved successfully:\n"
        f"{MODEL_PATH}"
    )


# ============================================================
# SAVE METRICS
# ============================================================

def save_metrics(
    metrics: dict,
):
    """
    Save model evaluation metrics as JSON.
    """

    print(
        "\nSaving model metrics..."
    )

    with METRICS_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4,
        )

    print(
        f"Metrics saved successfully:\n"
        f"{METRICS_PATH}"
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():
    """
    Execute the complete A²FaaS ML training workflow.
    """

    overall_start = time.perf_counter()

    try:

        # ----------------------------------------------------
        # 1. Load dataset
        # ----------------------------------------------------

        dataframe = load_dataset()

        # ----------------------------------------------------
        # 2. Prepare dataset
        # ----------------------------------------------------

        X, y = prepare_dataset(
            dataframe
        )

        # ----------------------------------------------------
        # 3. Train/validation split
        # ----------------------------------------------------

        (
            X_train,
            X_validation,
            y_train,
            y_validation,
        ) = split_dataset(
            X,
            y,
        )

        # ----------------------------------------------------
        # 4. Train model
        # ----------------------------------------------------

        (
            model,
            training_time,
        ) = train_model(
            X_train,
            y_train,
        )

        # ----------------------------------------------------
        # 5. Evaluate model
        # ----------------------------------------------------

        metrics = evaluate_model(
            model,
            X_validation,
            y_validation,
        )

        # ----------------------------------------------------
        # 6. Add training information
        # ----------------------------------------------------

        metrics[
            "training_samples"
        ] = int(
            len(X_train)
        )

        metrics[
            "validation_samples"
        ] = int(
            len(X_validation)
        )

        metrics[
            "training_time_seconds"
        ] = float(
            training_time
        )

        metrics[
            "features_before_encoding"
        ] = int(
            X.shape[1]
        )

        # ----------------------------------------------------
        # 7. Save artifacts
        # ----------------------------------------------------

        save_model(
            model
        )

        save_metrics(
            metrics
        )

        # ----------------------------------------------------
        # Overall completion
        # ----------------------------------------------------

        total_time = (
            time.perf_counter()
            - overall_start
        )

        print(
            "\n" + "=" * 72
        )

        print(
            "A²FaaS ML TRAINING COMPLETED SUCCESSFULLY"
        )

        print(
            "=" * 72
        )

        print(
            f"\nTotal pipeline time : "
            f"{total_time:.2f} seconds"
        )

        print(
            "\nGenerated artifacts:"
        )

        print(
            f"1. {MODEL_PATH.name}"
        )

        print(
            f"2. {METRICS_PATH.name}"
        )

        print(
            "\nThe trained ML pipeline is ready "
            "for firewall integration."
        )

    except Exception as error:

        print(
            "\n" + "=" * 72
        )

        print(
            "A²FaaS ML TRAINING FAILED"
        )

        print(
            "=" * 72
        )

        print(
            f"\nError:\n{error}"
        )

        raise


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()