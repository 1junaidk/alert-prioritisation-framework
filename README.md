# alert-prioritisation-framework

This project implements a data-driven alert prioritisation framework for cybersecurity incident response using the CICIDS2017 dataset.

## Features

- Network traffic preprocessing
- Threat intelligence enrichment using Spamhaus DROP list
- Asset criticality scoring
- Exposure/blast radius analysis
- Threat impact scoring
- Risk-based alert prioritisation
- Evaluation using accuracy, precision, recall and F1 score

## Included Files

- `pipeline_v2.py` – Main Python implementation
- `evaluation_results.txt` – Evaluation metrics and confusion matrix
- `Sample_of_prioritised_alerts.txt` – Sample framework output
- `sample_of_CICIDS2017.txt` – Small sample of CICIDS2017 flow records


```bash
python pipeline_v2.py
