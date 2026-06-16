import joblib
import os
import time
from src.email_client import ler_emails_nao_lidos

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'models')

def iniciar_phishguard():
    print("Iniciando os escudos do PhishGuard...")
    
    try:
        vetorizador = joblib.load(os.path.join(MODEL_DIR, 'vetorizador.pkl'))
        modelo = joblib.load(os.path.join(MODEL_DIR, 'random_forest.pkl'))
        print("Motor de Inteligência Artificial carregado com sucesso!\n")
    except FileNotFoundError:
        print("Erro: Modelos não encontrados. Rode 'python src/ml_engine.py' primeiro.")
        return

    print("🛡️ PhishGuard ativo. Monitorando a caixa de entrada...")
    print("Pressione 'Ctrl + C' para encerrar o software.\n")
    
    # Define o nível de rigor da IA (80% de certeza)
    LIMIAR_DE_ALERTA = 0.80 
    
    try:
        while True:
            novos_emails = ler_emails_nao_lidos()
            
            if novos_emails:
                print(f"[{time.strftime('%H:%M:%S')}] {len(novos_emails)} novo(s) e-mail(s) detectado(s). Analisando...")
                
                for email_data in novos_emails:
                    vetor_texto = vetorizador.transform([email_data['texto_completo']])
                    
                    # predict_proba retorna as porcentagens [chance_seguro, chance_phishing]
                    probabilidades = modelo.predict_proba(vetor_texto)[0]
                    chance_phishing = probabilidades[1] 
                    assunto = email_data['assunto']
                    
                    # Só classifica como golpe se a chance passar da nossa trava de segurança
                    if chance_phishing >= LIMIAR_DE_ALERTA:
                        print(f"🚨 PHISHING DETECTADO ({chance_phishing*100:.1f}%): '{assunto}'")
                    else:
                        print(f"✅ SEGURO ({chance_phishing*100:.1f}%): '{assunto}'")
            
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.")

if __name__ == "__main__":
    iniciar_phishguard()