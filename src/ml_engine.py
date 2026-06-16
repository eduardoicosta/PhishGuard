import pandas as pd
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Configuração de caminhos dinâmicos
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, 'data', 'phishing_email.csv')
MODEL_DIR = os.path.join(BASE_DIR, 'models')

def treinar_e_salvar_modelos():
    print("Iniciando o treinamento do PhishGuard com dados reais...")
    
    # 1. Carregando os 104MB de e-mails reais
    try:
        df = pd.read_csv(DATA_PATH)
    except FileNotFoundError:
        print(f"Erro: Arquivo não encontrado em {DATA_PATH}")
        return

    # Imprime os nomes originais só para descobrirmos onde estava o erro
    print(f"Colunas originais detectadas pelo Pandas: {df.columns.tolist()}")

    # TÁTICA À PROVA DE FALHAS: 
    # Se o CSV tiver mais de 2 colunas (ex: um ID no começo), pegamos só as duas últimas.
    if len(df.columns) > 2:
        df = df.iloc[:, -2:] 
        
    # Renomeamos as colunas forçadamente para nomes fáceis
    df.columns = ['texto', 'label']

    # Garante que a coluna 'label' seja numérica (se houver lixo, vira 'NaN')
    df['label'] = pd.to_numeric(df['label'], errors='coerce')

    # Limpeza: remove qualquer linha que ficou sem texto ou sem label numérico
    df = df.dropna(subset=['texto', 'label'])
    
    # Força os labels a serem números inteiros (0 ou 1) para o XGBoost não reclamar
    df['label'] = df['label'].astype(int)

    print(f"Total de e-mails validados para treino: {len(df)}")

    # 2. Convertendo os textos
    print("Vetorizando os textos (Isso pode levar alguns segundos/minutos)...")
    vetorizador = TfidfVectorizer()
    X = vetorizador.fit_transform(df['texto'])
    y = df['label']

    X_treino, X_teste, y_treino, y_teste = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Treinando Random Forest
    print("Treinando modelo Random Forest...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_treino, y_treino)
    rf_pred = rf_model.predict(X_teste)
    print(f"✅ Acurácia Random Forest: {accuracy_score(y_teste, rf_pred):.4f}")

    # 4. Treinando XGBoost
    print("Treinando modelo XGBoost...")
    xgb_model = XGBClassifier(eval_metric='logloss', random_state=42, n_jobs=-1)
    xgb_model.fit(X_treino, y_treino)
    xgb_pred = xgb_model.predict(X_teste)
    print(f"✅ Acurácia XGBoost: {accuracy_score(y_teste, xgb_pred):.4f}")

    # 5. Salvando os modelos
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vetorizador, os.path.join(MODEL_DIR, 'vetorizador.pkl'))
    joblib.dump(rf_model, os.path.join(MODEL_DIR, 'random_forest.pkl'))
    joblib.dump(xgb_model, os.path.join(MODEL_DIR, 'xgboost.pkl'))
    
    print("Modelos treinados e exportados para a pasta 'models' com sucesso!")

if __name__ == "__main__":
    treinar_e_salvar_modelos()