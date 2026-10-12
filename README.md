# A²FaaS — AI-Assisted Adaptive Firewall-as-a-Service

## Project Overview

A²FaaS is a web-based adaptive firewall prototype that combines machine learning-based network traffic risk prediction with Zero Trust access-control decisions. It provides a security dashboard for inspecting requests, viewing firewall decisions, and monitoring recorded security events.

## Key Features

- **Adaptive Firewall:** Evaluates requests and produces ALLOW, CHALLENGE, or BLOCK decisions.
- **Machine Learning:** Uses Logistic Regression to classify network traffic as normal or attack traffic.
- **Zero Trust Security:** Evaluates identity verification, device trust, request context, and policy rules.
- **Security Dashboard:** Displays request statistics, firewall analysis, ML information, and traffic records.
- **Protected Sample Application:** Demonstrates authentication and firewall-controlled access.
- **Cloud Deployment:** Frontend, backend, and sample application are deployed on Render.
- **Containerization:** Docker configuration is included in the repository.

## Technology Stack

- Frontend: React, Vite, JavaScript, CSS
- Backend: Python, FastAPI, Uvicorn
- Machine Learning: scikit-learn, pandas, joblib
- Dataset: UNSW-NB15 training dataset
- Protected Sample Application: Flask
- Database: Project database implementation
- Deployment: Render
- Containerization: Docker

## Machine Learning

The training pipeline in `ml/train_model.py` prepares network traffic features, creates a stratified 80:20 training/validation split, trains a Logistic Regression classifier, evaluates the model, and saves the model and metrics.

The saved metrics in `ml/model_metrics.json` report:

| Metric | Recorded value |
|---|---:|
| Accuracy | 93.23% |
| Precision | 95.00% |
| Recall | 95.06% |
| F1-score | 95.03% |

These values are recorded evaluation results; reproduce the training run to independently verify them.

## Zero Trust Policy

The firewall evaluates the Zero Trust decision alongside the ML risk assessment. A policy-level BLOCK decision remains BLOCK even when the ML risk level is LOW. Requests that do not satisfy the required verification checks can receive CHALLENGE.

## Deployment

- Frontend: https://a2faas-frontend.onrender.com
- Backend API: https://a2faas.onrender.com
- API documentation: https://a2faas.onrender.com/docs
- Protected sample application: https://a2faas-sample-app.onrender.com

## Verified Live Tests

The following behaviors were tested against the deployed API and sample application:

1. A permitted GET request with identity and device trust marked true returned ALLOW.
2. A GET request with identity and device trust marked false returned CHALLENGE.
3. A prohibited TRACE request returned BLOCK, even with identity and device trust marked true.
4. The protected sample application displayed its login page and allowed access after successful authentication.
5. Logout returned the user to the login page.
6. The dashboard displayed firewall analysis results and traffic information.

These tests verify the specific flows listed above, not every possible security condition.

## Repository Structure

```text
A2FaaS/
├── backend/       # Backend API and firewall analysis
├── database/      # Database implementation
├── docker/        # Docker-related files
├── docs/          # Project documentation
├── ml/            # Model, training pipeline, dataset, and metrics
├── sample_app/    # Protected Flask sample application
├── security/      # Zero Trust and security policy code
├── src/           # React frontend
├── public/        # Static frontend assets
├── tests/         # Reserved for automated tests
├── docker-compose.yml
├── package.json
├── requirements.txt
└── README.md
```

## Running Locally

Install the Python dependencies using the repository's requirements file and install frontend dependencies using npm. Configure the required environment variables for the backend and sample application before starting services.

Refer to the backend configuration and deployment settings for the required environment variables and service commands. Do not commit passwords, secret keys, or other credentials to the repository.

## Future Improvements

- Add automated unit and integration tests.
- Document reproducible ML evaluation and dataset provenance.
- Expand security-event auditing and policy tests.
- Document local setup and deployment configuration in detail.

## License

Specify the project's license here if one has been selected.