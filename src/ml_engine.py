import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "phishing_ptbr.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")


def _carregar_dataset(caminho: str) -> pd.DataFrame:
    if not os.path.exists(caminho):
        raise FileNotFoundError(
            f"Dataset não encontrado em {caminho}. "
            "Execute: python scripts/gerar_dataset_ptbr.py"
        )

    df = pd.read_csv(caminho)

    if "texto" not in df.columns or "label" not in df.columns:
        raise ValueError("O CSV deve conter as colunas 'texto' e 'label'.")

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["texto", "label"])
    df["texto"] = df["texto"].astype(str).str.strip()
    df = df[df["texto"].str.len() > 0]
    df["label"] = df["label"].astype(int)

    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("Os labels devem ser 0 (seguro) ou 1 (phishing).")

    return df


def _criar_vetorizador() -> TfidfVectorizer:
    """Parâmetros ajustados para base pequena em português (~150-200 exemplos)."""
    return TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        analyzer="word",
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.95,
        max_features=5000,
        sublinear_tf=True,
        token_pattern=r"(?u)\b[\wáàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]+\b",
    )


def treinar_e_salvar_modelos():
    print("Iniciando treinamento do PhishGuard (dataset PT-BR)...")

    try:
        df = _carregar_dataset(DATA_PATH)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Erro: {exc}")
        return

    total_seguros = (df["label"] == 0).sum()
    total_phishing = (df["label"] == 1).sum()
    print(f"Total de e-mails: {len(df)} ({total_seguros} seguros, {total_phishing} phishing)")

    vetorizador = _criar_vetorizador()
    X = vetorizador.fit_transform(df["texto"])
    y = df["label"]

    X_treino, X_teste, y_treino, y_teste = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print("Treinando Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=80,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf_model.fit(X_treino, y_treino)
    rf_pred = rf_model.predict(X_teste)
    print(f"Acurácia Random Forest: {accuracy_score(y_teste, rf_pred):.4f}")

    print("Treinando XGBoost...")
    xgb_model = XGBClassifier(
        n_estimators=80,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    xgb_model.fit(X_treino, y_treino)
    xgb_pred = xgb_model.predict(X_teste)
    print(f"Acurácia XGBoost: {accuracy_score(y_teste, xgb_pred):.4f}")

    print("\nRelatório Random Forest:")
    print(classification_report(y_teste, rf_pred, target_names=["Seguro", "Phishing"]))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vetorizador, os.path.join(MODEL_DIR, "vetorizador.pkl"))
    joblib.dump(rf_model, os.path.join(MODEL_DIR, "random_forest.pkl"))
    joblib.dump(xgb_model, os.path.join(MODEL_DIR, "xgboost.pkl"))

    print(f"\nModelos salvos em '{MODEL_DIR}' com sucesso!")


if __name__ == "__main__":
    treinar_e_salvar_modelos()
