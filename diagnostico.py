from src.email_client import conectar_imap

def raio_x():
    print("Conectando ao Google...")
    mail = conectar_imap()
    
    if not mail:
        print("Falha na conexão.")
        return

    # Acessa a caixa de entrada
    status, total = mail.select('INBOX')
    print(f"Status da Caixa: {status}")
    print(f"Total de e-mails (lidos e não lidos) na INBOX: {total[0].decode('utf-8')}")
    
    # Procura especificamente os não lidos
    status_unseen, mensagens_unseen = mail.search(None, 'UNSEEN')
    ids = mensagens_unseen[0].decode('utf-8').split()
    
    print(f"Quantidade de e-mails marcados como NÃO LIDOS agora: {len(ids)}")
    if len(ids) > 0:
        print(f"IDs dos e-mails não lidos: {ids}")
    else:
        print("O Google jura que não há nenhum e-mail não lido nesta pasta.")
        
    mail.logout()

if __name__ == "__main__":
    raio_x()