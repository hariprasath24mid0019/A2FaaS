# A²FaaS — Technical Project Report

## 1. Introduction

A²FaaS (AI-Assisted Adaptive Firewall-as-a-Service) is a web-based adaptive firewall prototype that combines machine learning-based network traffic classification with Zero Trust access-control policies. The system provides a dashboard for analyzing requests, viewing firewall decisions, and monitoring security events.

## 2. Project Objectives

- Develop a web-based interface for firewall monitoring and analysis.
- Use machine learning to classify network traffic as normal or attack traffic.
- Apply Zero Trust policies to evaluate identity verification and device trust.
- Produce ALLOW, CHALLENGE, or BLOCK decisions.
- Demonstrate protected resource access through a sample application.
- Deploy the frontend, backend, and sample application to the cloud.

## 3. System Architecture

The application consists of the following components:

### 3.1 Frontend

The frontend is built using React, Vite, JavaScript, and CSS. It provides the dashboard and interfaces for firewall analysis, machine learning information, Zero Trust status, and traffic records.

### 3.2 Backend

The backend uses Python, FastAPI, and Uvicorn to expose API endpoints and process firewall analysis requests.

### 3.3 Machine Learning Module

The machine learning module uses a Logistic Regression classifier and the UNSW-NB15 training dataset. Its training pipeline prepares the data, performs a stratified training-validation split, evaluates the model, and saves the trained model and evaluation metrics.

### 3.4 Zero Trust Security

The Zero Trust component evaluates access conditions, including identity verification, device trust, and policy rules. A policy-level BLOCK decision remains BLOCK even when the machine learning risk level is LOW.

### 3.5 Protected Sample Application

The sample application demonstrates authentication and firewall-controlled access to a protected resource.

## 4. Machine Learning Methodology

The model training pipeline is implemented in `ml/train_model.py`.

The documented workflow includes:

1. Load the UNSW-NB15 training dataset.
2. Prepare the dataset and target labels.
3. Separate numerical and categorical features.
4. Apply numerical and categorical preprocessing.
5. Split the dataset into training and validation subsets using an 80:20 ratio.
6. Train a Logistic Regression classifier.
7. Evaluate the model using classification metrics.
8. Save the trained model and evaluation metrics.

The saved metrics in `ml/model_metrics.json` report the following results:

| Metric | Recorded value |
|---|---:|
| Accuracy | 93.23% |
| Precision | 95.00% |
| Recall | 95.06% |
| F1-score | 95.03% |

These are the recorded evaluation results. An independent reproduction of the training process is required to verify them.

## 5. Firewall Decision Process

The system evaluates incoming request information and combines machine learning risk assessment with access-control policy decisions.

The three principal outcomes are:

- **ALLOW:** The request satisfies the applicable access requirements.
- **CHALLENGE:** Additional verification is required before access is granted.
- **BLOCK:** The request is prohibited by the applicable policy.

The final decision depends on the implemented firewall and Zero Trust rules. A low machine learning risk score does not override an explicit policy-level BLOCK decision.

## 6. Cloud Deployment

The project components are deployed on Render.

- **Frontend:** https://a2faas-frontend.onrender.com
- **Backend API:** https://a2faas.onrender.com
- **API documentation:** https://a2faas.onrender.com/docs
- **Protected sample application:** https://a2faas-sample-app.onrender.com

The deployed API can be inspected through its interactive documentation interface.

## 7. Live Testing and Observations

The following scenarios were tested against the deployed system:

1. A GET request with identity verification and device trust enabled returned ALLOW.
2. A GET request without identity verification and device trust returned CHALLENGE.
3. A prohibited TRACE request returned BLOCK, even when identity verification and device trust were enabled.
4. The sample application's login page loaded successfully.
5. Successful authentication allowed access to the protected resource when authorized by the firewall.
6. Logging out returned the user to the login page.
7. The dashboard displayed firewall analysis results and traffic information.

These observations apply to the specific scenarios tested. They do not establish that every possible attack or security condition has been tested.

## 8. Technologies Used

- Frontend: React, Vite, JavaScript, CSS
- Backend: Python, FastAPI, Uvicorn
- Machine learning: scikit-learn, pandas, joblib
- Dataset: UNSW-NB15 training dataset
- Sample application: Flask
- Cloud deployment: Render
- Containerization: Docker configuration included in the repository

The exact database implementation and configuration should be documented after verifying the project's database files and settings.

## 9. Current Limitations

- The documented live tests cover selected scenarios rather than exhaustive security validation.
- Automated unit and integration tests still need to be added.
- The model evaluation results need an independently reproducible training run.
- Detailed local setup and environment configuration need further documentation.
- Additional policy tests and security-event auditing would improve validation.

## 10. Future Enhancements

- Develop automated unit and integration tests.
- Expand firewall and Zero Trust policy test coverage.
- Improve security-event logging and auditing.
- Document reproducible model training and evaluation.
- Provide complete local installation and deployment instructions.
- Evaluate additional models and compare their performance.

## 11. Conclusion

A²FaaS demonstrates an integrated approach to adaptive firewall analysis by combining machine learning-based traffic classification, Zero Trust access policies, a web-based security dashboard, and a protected sample application. The deployed prototype has been tested against selected access-control scenarios. Further automated testing, reproducible model evaluation, and detailed configuration documentation are recommended to strengthen the system.
