import imaplib
import smtplib
import email
import os
from email.header import decode_header
from email.utils import parseaddr
from email.message import EmailMessage

def obter_credenciais():
    usuario = os.getenv("EMAIL_USUARIO")
    senha = os.getenv("EMAIL_SENHA")
    return usuario, senha

def conectar_imap():
    usuario, senha = obter_credenciais()
    if not usuario or not senha:
        return None
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(usuario, senha)
        return mail
    except Exception as e:
        print(f"Falha ao conectar no IMAP: {e}")
        return None

def decodificar_texto(texto_bruto):
    if not texto_bruto: return ""
    try:
        partes = decode_header(texto_bruto)
        texto_final = ""
        for texto, encoding in partes:
            if isinstance(texto, bytes):
                texto_final += texto.decode(encoding if encoding else 'utf-8', errors='ignore')
            else:
                texto_final += str(texto)
        return texto_final
    except:
        return str(texto_bruto)

def ler_ultimos_emails(quantidade=150):
    mail = conectar_imap()
    if not mail: return []

    mail.select('inbox')
    # Usamos UID SEARCH para obter os IDs únicos reais do servidor, necessários para exclusão
    status, mensagens = mail.uid('search', None, 'ALL')
    ids_emails = mensagens[0].split()[-quantidade:]
    ids_emails.reverse() # Inverte para mostrar do mais novo para o mais velho
    
    emails_extraidos = []

    for uid_bytes in ids_emails:
        status, dados_msg = mail.uid('fetch', uid_bytes, '(RFC822)')
        for resposta in dados_msg:
            if isinstance(resposta, tuple):
                msg = email.message_from_bytes(resposta[1])
                
                assunto = decodificar_texto(msg['Subject']) if msg['Subject'] else "Sem Assunto"
                remetente_raw = msg.get('From', 'Desconhecido')
                nome_remetente, email_remetente = parseaddr(remetente_raw)
                nome_remetente = decodificar_texto(nome_remetente) 
                
                remetente_formatado = f"{nome_remetente} <{email_remetente}>" if nome_remetente else email_remetente
                
                corpo_texto = ""
                corpo_html = ""
                
                if msg.is_multipart():
                    for part in msg.walk():
                        tipo = part.get_content_type()
                        if tipo == "text/plain":
                            try: corpo_texto = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            except: pass
                        elif tipo == "text/html":
                            try: corpo_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            except: pass
                else:
                    tipo = msg.get_content_type()
                    try:
                        decodificado = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                        if tipo == "text/html": corpo_html = decodificado
                        else: corpo_texto = decodificado
                    except: pass
                
                if not corpo_html:
                    corpo_html = f"<pre style='font-family: sans-serif; padding: 20px; color: black; background: white;'>{corpo_texto}</pre>"
                if not corpo_texto:
                    corpo_texto = corpo_html 
                
                emails_extraidos.append({
                    'uid': uid_bytes.decode('utf-8'),
                    'email_resposta': email_remetente,
                    'assunto': assunto,
                    'remetente': remetente_formatado,
                    'texto_completo': f"{assunto} {corpo_texto}",
                    'html_completo': corpo_html
                })
    
    mail.logout()
    return emails_extraidos

def mover_para_lixeira(uid_email):
    mail = conectar_imap()
    if not mail: return False
    
    try:
        mail.select('inbox')
        
        # 1. Tenta copiar para a lixeira em Português
        pasta_lixeira = '[Gmail]/Lixeira'
        status, resposta = mail.uid('COPY', uid_email, pasta_lixeira)
        
        # 2. Se a conta do Google estiver em Inglês, o nome da pasta muda. Fazemos o fallback.
        if status != 'OK':
            pasta_lixeira = '[Gmail]/Trash'
            status, resposta = mail.uid('COPY', uid_email, pasta_lixeira)
            
        # 3. Se a cópia para a lixeira deu certo, deletamos a versão da Caixa de Entrada original
        if status == 'OK':
            mail.uid('STORE', uid_email, '+FLAGS', '(\\Deleted)')
            mail.expunge() # Esvazia o "lixo" local da pasta Inbox
            mail.logout()
            return True
        else:
            print("Não foi possível encontrar a pasta de Lixeira no servidor.")
            mail.logout()
            return False
            
    except Exception as e:
        print(f"Erro crítico ao tentar excluir: {e}")
        return False

def enviar_resposta(destinatario, assunto_original, corpo_mensagem):
    usuario, senha = obter_credenciais()
    if not usuario or not senha: return False
    
    try:
        msg = EmailMessage()
        msg.set_content(corpo_mensagem)
        msg['Subject'] = f"Re: {assunto_original}"
        msg['From'] = usuario
        msg['To'] = destinatario

        # Conecta no SMTP do Google para realizar o envio bidirecional
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(usuario, senha)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Erro SMTP: {e}")
        return False