import sys
import os
import joblib
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QStackedWidget, QHBoxLayout, 
                             QFrame, QSpacerItem, QSizePolicy, QGraphicsDropShadowEffect,
                             QSplitter, QListWidget, QSlider, QTextEdit, QMessageBox, QDialog)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QCursor, QColor, QPixmap, QIcon

# Importa as funções do backend (leitura, exclusão e envio)
from src.email_client import ler_ultimos_emails, mover_para_lixeira, enviar_resposta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'models')

# ==================== JANELA DE RESPOSTA (POPUP) ====================
class DialogoResposta(QDialog):
    def __init__(self, remetente, assunto, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nova Resposta Segura")
        self.setFixedSize(600, 450)
        self.setStyleSheet("background-color: #161b22; color: #e6edf3;")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        lbl_info = QLabel(f"<b>Para:</b> {remetente}<br><b>Assunto:</b> Re: {assunto}")
        lbl_info.setFont(QFont("Segoe UI", 11))
        lbl_info.setStyleSheet("background-color: #0d1117; padding: 10px; border-radius: 5px; border: 1px solid #30363d;")
        
        self.caixa_texto = QTextEdit()
        self.caixa_texto.setPlaceholderText("Escreva sua resposta aqui...")
        self.caixa_texto.setStyleSheet("background-color: #010409; color: #c9d1d9; border: 1px solid #30363d; border-radius: 5px; padding: 10px; font-size: 14px;")
        
        layout_botoes = QHBoxLayout()
        btn_cancelar = QPushButton("Cancelar")
        btn_cancelar.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_cancelar.setStyleSheet("background-color: transparent; border: 1px solid #30363d; padding: 10px 20px; border-radius: 5px; font-weight: bold;")
        btn_cancelar.clicked.connect(self.reject)
        
        btn_enviar = QPushButton("Enviar Resposta")
        btn_enviar.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_enviar.setStyleSheet("background-color: #238636; color: white; font-weight: bold; padding: 10px 20px; border-radius: 5px; border: none;")
        btn_enviar.clicked.connect(self.accept)
        
        layout_botoes.addStretch()
        layout_botoes.addWidget(btn_cancelar)
        layout_botoes.addWidget(btn_enviar)
        
        layout.addWidget(lbl_info)
        layout.addSpacing(10)
        layout.addWidget(self.caixa_texto)
        layout.addSpacing(10)
        layout.addLayout(layout_botoes)

    def obter_texto(self):
        return self.caixa_texto.toPlainText().strip()

# ==================== MOTOR EM SEGUNDO PLANO ====================
class LeitorDeEmailsWorker(QThread):
    sinal_resultado = pyqtSignal(list)

    def __init__(self, vetorizador, modelo, dominios_whitelist, limiar_alerta):
        super().__init__()
        self.vetorizador = vetorizador
        self.modelo = modelo
        self.dominios_confiaveis = dominios_whitelist
        self.limiar_alerta = limiar_alerta

    def run(self):
        emails = ler_ultimos_emails(150) # Busca de 150 e-mails
        resultados = []

        if emails:
            for email_data in emails:
                remetente = email_data['remetente']
                texto_puro = email_data['texto_completo']
                html = email_data['html_completo']
                
                dominio_remetente = "desconhecido"
                if "@" in remetente:
                    dominio_remetente = remetente.split('@')[-1].replace('>', '').strip().lower()

                chance_phishing = 0.0

                if dominio_remetente in self.dominios_confiaveis:
                    chance_phishing = 0.0 
                else:
                    vetor_texto = self.vetorizador.transform([texto_puro])
                    probabilidades = self.modelo.predict_proba(vetor_texto)[0]
                    chance_phishing = probabilidades[1]
                    
                    tem_link = "http" in html.lower() or "www" in html.lower() or "<a href" in html.lower()
                    if chance_phishing > self.limiar_alerta and not tem_link:
                        chance_phishing = chance_phishing * 0.5

                resultados.append({
                    'uid': email_data['uid'],
                    'email_resposta': email_data['email_resposta'],
                    'assunto': email_data['assunto'],
                    'remetente': email_data['remetente'],
                    'html_completo': email_data['html_completo'],
                    'chance_phishing': chance_phishing,
                    'limiar_usado': self.limiar_alerta
                })
        
        self.sinal_resultado.emit(resultados)

# ==================== INTERFACE GRÁFICA ====================
class PhishGuardApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PhishGuard - Security Operations Center")
        self.setMinimumSize(1200, 800)

        self.email_selecionado_atual = None 
        self.limiar_alerta = 0.60
        self.dominios_whitelist = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'aws.amazon.com',
            'github.com', 'gitlab.com', 'linkedin.com', 'slack.com', 'zoom.us', 'atlassian.com',
            'gov.br', 'sp.gov.br', 'fiap.com.br', 'ccee.org.br',
            'itau.com.br', 'nubank.com.br', 'bb.com.br', 'caixa.gov.br', 'bradesco.com.br', 'picpay.com',
            'mercadolivre.com.br', 'ifood.com.br', 'uber.com', 'netflix.com'
        ]

        caminho_logo = os.path.join(BASE_DIR, 'assets', 'logo.png')
        if os.path.exists(caminho_logo):
            self.setWindowIcon(QIcon(caminho_logo))

        self.carregar_ia()

        self.stacked_principal = QStackedWidget()
        self.setCentralWidget(self.stacked_principal)

        self.tela_login = self.criar_tela_login()
        self.tela_app = self.criar_layout_app()

        self.stacked_principal.addWidget(self.tela_login)
        self.stacked_principal.addWidget(self.tela_app)

        self.aplicar_estilo()
        self.worker = None

    def carregar_ia(self):
        try:
            self.vetorizador = joblib.load(os.path.join(MODEL_DIR, 'vetorizador.pkl'))
            self.modelo = joblib.load(os.path.join(MODEL_DIR, 'random_forest.pkl'))
        except FileNotFoundError:
            print("Erro: Modelos de IA não encontrados. Rode o ml_engine.py primeiro.")
            sys.exit(1)

    def criar_tela_login(self):
        widget = QWidget()
        layout_principal = QVBoxLayout(widget)
        layout_principal.setAlignment(Qt.AlignmentFlag.AlignCenter)

        container_login = QFrame()
        container_login.setFixedSize(450, 480)
        container_login.setObjectName("loginContainer")
        
        sombra = QGraphicsDropShadowEffect()
        sombra.setBlurRadius(30)
        sombra.setXOffset(0)
        sombra.setYOffset(10)
        sombra.setColor(QColor(0, 0, 0, 150))
        container_login.setGraphicsEffect(sombra)

        layout_login = QVBoxLayout(container_login)
        layout_login.setContentsMargins(40, 40, 40, 40)
        layout_login.setSpacing(20)

        lbl_icone = QLabel()
        caminho_logo = os.path.join(BASE_DIR, 'assets', 'logo.png')
        if os.path.exists(caminho_logo):
            pixmap = QPixmap(caminho_logo).scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            lbl_icone.setPixmap(pixmap)
        else:
            lbl_icone.setText("🛡️")
            lbl_icone.setFont(QFont("Segoe UI", 48))
        lbl_icone.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        lbl_titulo = QLabel("PhishGuard")
        lbl_titulo.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        lbl_titulo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_titulo.setObjectName("titulo")
        
        self.input_email = QLineEdit()
        self.input_email.setPlaceholderText("E-mail corporativo")
        self.input_email.setFixedHeight(45)

        self.input_senha = QLineEdit()
        self.input_senha.setPlaceholderText("Senha de Aplicativo (16 dígitos)")
        self.input_senha.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_senha.setFixedHeight(45)

        btn_conectar = QPushButton("AUTENTICAR")
        btn_conectar.setFixedHeight(50)
        btn_conectar.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_conectar.clicked.connect(self.validar_login)

        self.lbl_erro = QLabel("")
        self.lbl_erro.setObjectName("textoErro")
        self.lbl_erro.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout_login.addWidget(lbl_icone)
        layout_login.addWidget(lbl_titulo)
        layout_login.addSpacing(10)
        layout_login.addWidget(self.input_email)
        layout_login.addWidget(self.input_senha)
        layout_login.addSpacing(15)
        layout_login.addWidget(btn_conectar)
        layout_login.addWidget(self.lbl_erro)

        layout_principal.addWidget(container_login)
        return widget

    def criar_layout_app(self):
        widget = QWidget()
        layout_principal = QHBoxLayout(widget) 
        layout_principal.setContentsMargins(0, 0, 0, 0)
        layout_principal.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        layout_sidebar = QVBoxLayout(sidebar)
        layout_sidebar.setContentsMargins(20, 30, 20, 30)
        layout_sidebar.setSpacing(15)

        header_sidebar = QHBoxLayout()
        lbl_icone_sidebar = QLabel()
        caminho_logo = os.path.join(BASE_DIR, 'assets', 'logo.png')
        if os.path.exists(caminho_logo):
            pixmap = QPixmap(caminho_logo).scaled(30, 30, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            lbl_icone_sidebar.setPixmap(pixmap)
        else:
            lbl_icone_sidebar.setText("🛡️")
        
        lbl_texto_logo = QLabel("PhishGuard")
        lbl_texto_logo.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        lbl_texto_logo.setStyleSheet("color: #e6edf3;")
        
        header_sidebar.addWidget(lbl_icone_sidebar)
        header_sidebar.addWidget(lbl_texto_logo)
        header_sidebar.addStretch()

        linha = QFrame()
        linha.setFrameShape(QFrame.Shape.HLine)
        linha.setStyleSheet("background-color: #30363d;")

        self.lbl_avatar = QLabel("👤")
        self.lbl_avatar.setFixedSize(40, 40)
        self.lbl_avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_avatar.setObjectName("avatarUsuario")
        
        self.lbl_email_logado = QLabel("analista@dominio.com")
        self.lbl_email_logado.setFont(QFont("Segoe UI", 10))
        self.lbl_email_logado.setStyleSheet("color: #8b949e;")
        self.lbl_email_logado.setWordWrap(True)

        layout_perfil = QHBoxLayout()
        layout_perfil.addWidget(self.lbl_avatar)
        layout_perfil.addWidget(self.lbl_email_logado)

        btn_inbox = QPushButton("📥 Caixa de Entrada")
        btn_inbox.setObjectName("btnMenu")
        btn_inbox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_inbox.clicked.connect(lambda: self.stacked_telas.setCurrentIndex(0))

        btn_config = QPushButton("⚙️ Configurações da IA")
        btn_config.setObjectName("btnMenu")
        btn_config.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_config.clicked.connect(lambda: self.stacked_telas.setCurrentIndex(1))

        btn_sair = QPushButton("🚪 Fazer Logoff")
        btn_sair.setObjectName("btnMenuSair")
        btn_sair.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_sair.clicked.connect(self.fazer_logoff)

        layout_sidebar.addLayout(header_sidebar)
        layout_sidebar.addSpacing(20)
        layout_sidebar.addLayout(layout_perfil)
        layout_sidebar.addSpacing(10)
        layout_sidebar.addWidget(linha)
        layout_sidebar.addSpacing(10)
        layout_sidebar.addWidget(btn_inbox)
        layout_sidebar.addWidget(btn_config)
        layout_sidebar.addStretch()
        layout_sidebar.addWidget(btn_sair)

        area_conteudo = QFrame()
        area_conteudo.setObjectName("areaConteudo")
        layout_conteudo = QVBoxLayout(area_conteudo)
        layout_conteudo.setContentsMargins(0, 0, 0, 0)

        self.stacked_telas = QStackedWidget()
        self.tela_inbox = self.criar_tela_inbox()
        self.tela_config = self.criar_tela_config()
        
        self.stacked_telas.addWidget(self.tela_inbox)
        self.stacked_telas.addWidget(self.tela_config)

        layout_conteudo.addWidget(self.stacked_telas)

        layout_principal.addWidget(sidebar)
        layout_principal.addWidget(area_conteudo)

        return widget

    def criar_tela_inbox(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QHBoxLayout()
        lbl_titulo = QLabel("Caixa de Entrada Blindada")
        lbl_titulo.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        
        btn_atualizar = QPushButton("Atualizar E-mails")
        btn_atualizar.setObjectName("btnAcao")
        btn_atualizar.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_atualizar.clicked.connect(self.buscar_emails)

        header.addWidget(lbl_titulo)
        header.addStretch()
        header.addWidget(btn_atualizar)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.lista_emails = QListWidget()
        self.lista_emails.setObjectName("listaEmails")
        self.lista_emails.currentRowChanged.connect(self.mostrar_detalhes_email)
        
        painel_leitura = QWidget()
        layout_leitura = QVBoxLayout(painel_leitura)
        layout_leitura.setContentsMargins(0, 0, 0, 0)
        
        self.banner_ia = QLabel("Selecione um e-mail para iniciar a varredura.")
        self.banner_ia.setObjectName("bannerIA")
        self.banner_ia.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.banner_ia.setFixedHeight(50)
        self.banner_ia.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        
        # ==================== BARRA DE AÇÕES (RESPONDER E LIXEIRA) ====================
        barra_acoes = QFrame()
        barra_acoes.setFixedHeight(50)
        barra_acoes.setStyleSheet("background-color: #161b22; border-bottom: 1px solid #30363d; border-left: 1px solid #30363d; border-right: 1px solid #30363d; border-radius: 0 0 5px 5px;")
        layout_acoes = QHBoxLayout(barra_acoes)
        layout_acoes.setContentsMargins(15, 0, 15, 0)
        
        self.btn_responder = QPushButton("↩️ Responder")
        self.btn_responder.setObjectName("btnResponder")
        self.btn_responder.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_responder.clicked.connect(self.acao_responder)
        self.btn_responder.setEnabled(False)
        
        self.btn_lixeira = QPushButton("🗑️ Mover para Lixeira")
        self.btn_lixeira.setObjectName("btnLixeira")
        self.btn_lixeira.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_lixeira.clicked.connect(self.acao_lixeira)
        self.btn_lixeira.setEnabled(False)

        layout_acoes.addWidget(self.btn_responder)
        layout_acoes.addWidget(self.btn_lixeira)
        layout_acoes.addStretch()
        # ============================================================================
        
        self.area_texto_email = QWebEngineView()
        self.area_texto_email.setObjectName("areaLeitura")

        layout_leitura.addWidget(self.banner_ia)
        layout_leitura.addWidget(barra_acoes)
        layout_leitura.addWidget(self.area_texto_email)

        splitter.addWidget(self.lista_emails)
        splitter.addWidget(painel_leitura)
        splitter.setSizes([350, 800])

        layout.addLayout(header)
        layout.addSpacing(10)
        layout.addWidget(splitter)
        return widget

    def criar_tela_config(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        lbl_titulo = QLabel("Configurações do Motor de Inteligência Artificial")
        lbl_titulo.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        
        lbl_whitelist = QLabel("Domínios Confiáveis (Whitelist)")
        lbl_whitelist.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl_whitelist_desc = QLabel("E-mails originados destes domínios não serão classificados como Phishing. (Um por linha)")
        lbl_whitelist_desc.setStyleSheet("color: #8b949e;")

        self.txt_whitelist = QTextEdit()
        self.txt_whitelist.setObjectName("inputArea")
        self.txt_whitelist.setFixedHeight(250)
        self.txt_whitelist.setPlainText("\n".join(self.dominios_whitelist))

        lbl_sensibilidade = QLabel("Sensibilidade do Alerta (Threshold)")
        lbl_sensibilidade.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl_sensibilidade_desc = QLabel("Define a porcentagem mínima de risco para a IA considerar um e-mail como ataque.")
        lbl_sensibilidade_desc.setStyleSheet("color: #8b949e;")

        layout_slider = QHBoxLayout()
        self.slider_sensibilidade = QSlider(Qt.Orientation.Horizontal)
        self.slider_sensibilidade.setMinimum(10)
        self.slider_sensibilidade.setMaximum(95)
        self.slider_sensibilidade.setValue(int(self.limiar_alerta * 100))
        self.slider_sensibilidade.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.slider_sensibilidade.setTickInterval(10)
        
        self.lbl_valor_slider = QLabel(f"{self.slider_sensibilidade.value()}%")
        self.lbl_valor_slider.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.lbl_valor_slider.setStyleSheet("color: #58a6ff;")
        
        self.slider_sensibilidade.valueChanged.connect(lambda v: self.lbl_valor_slider.setText(f"{v}%"))

        layout_slider.addWidget(self.slider_sensibilidade)
        layout_slider.addWidget(self.lbl_valor_slider)

        btn_salvar = QPushButton("Salvar Configurações")
        btn_salvar.setObjectName("btnPrimario")
        btn_salvar.setFixedWidth(200)
        btn_salvar.setFixedHeight(45)
        btn_salvar.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_salvar.clicked.connect(self.salvar_configuracoes)

        layout.addWidget(lbl_titulo)
        layout.addSpacing(30)
        layout.addWidget(lbl_whitelist)
        layout.addWidget(lbl_whitelist_desc)
        layout.addWidget(self.txt_whitelist)
        layout.addSpacing(30)
        layout.addWidget(lbl_sensibilidade)
        layout.addWidget(lbl_sensibilidade_desc)
        layout.addLayout(layout_slider)
        layout.addSpacing(40)
        layout.addWidget(btn_salvar)

        return widget

    def salvar_configuracoes(self):
        texto_limpo = self.txt_whitelist.toPlainText().strip()
        novos_dominios = [d.strip().lower() for d in texto_limpo.split('\n') if d.strip()]
        self.dominios_whitelist = novos_dominios
        self.limiar_alerta = self.slider_sensibilidade.value() / 100.0
        QMessageBox.information(self, "Sucesso", "Configurações da Inteligência Artificial atualizadas com sucesso. As regras já serão aplicadas na próxima varredura.")

    def validar_login(self):
        email = self.input_email.text().strip()
        senha = self.input_senha.text().strip()

        if not email or not senha:
            self.lbl_erro.setText("Por favor, preencha todos os campos.")
            return
            
        self.lbl_erro.setText("")
        os.environ["EMAIL_USUARIO"] = email
        os.environ["EMAIL_SENHA"] = senha
        
        self.lbl_email_logado.setText(email)
        primeira_letra = email[0].upper() if email else "👤"
        self.lbl_avatar.setText(primeira_letra)
        
        self.stacked_principal.setCurrentIndex(1) 
        self.stacked_telas.setCurrentIndex(0) 
        self.buscar_emails()

    def buscar_emails(self):
        self.btn_responder.setEnabled(False)
        self.btn_lixeira.setEnabled(False)
        self.email_selecionado_atual = None
        self.banner_ia.setText("Sincronizando com o Google Workspace (Isso pode levar alguns segundos)...")
        self.banner_ia.setStyleSheet("background-color: #1f6feb; color: white; border-radius: 5px 5px 0 0;")
        self.lista_emails.clear()
        self.area_texto_email.setHtml("<html><body style='background-color: #ffffff;'></body></html>")
        
        self.worker = LeitorDeEmailsWorker(self.vetorizador, self.modelo, self.dominios_whitelist, self.limiar_alerta)
        self.worker.sinal_resultado.connect(self.atualizar_interface_com_emails)
        self.worker.start()

    def atualizar_interface_com_emails(self, resultados):
        self.dados_emails = resultados 
        
        if not resultados:
            self.banner_ia.setText("Nenhum e-mail encontrado na Caixa de Entrada.")
            self.banner_ia.setStyleSheet("background-color: #30363d; color: #8b949e; border-radius: 5px 5px 0 0;")
            return
            
        self.banner_ia.setText(f"{len(resultados)} e-mails processados e analisados.")
        self.banner_ia.setStyleSheet("background-color: #238636; color: white; border-radius: 5px 5px 0 0;")
        
        for email in resultados:
            self.lista_emails.addItem(f"{email['assunto']}\nDe: {email['remetente']}")

    def mostrar_detalhes_email(self, index):
        if index < 0: return
            
        self.email_selecionado_atual = self.dados_emails[index]
        self.btn_responder.setEnabled(True)
        self.btn_lixeira.setEnabled(True)
        
        chance_phishing = self.email_selecionado_atual['chance_phishing']
        remetente = self.email_selecionado_atual['remetente']
        limiar = self.email_selecionado_atual['limiar_usado']
        
        html_responsivo = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ margin: 0; padding: 15px; background-color: #ffffff; font-family: Arial; overflow-x: hidden; }}
            img {{ max-width: 100% !important; height: auto !important; }}
            table {{ max-width: 100% !important; width: auto !important; margin: 0 auto; }}
            .phishguard-wrapper {{ max-width: 800px; margin: 0 auto; }}
        </style></head>
        <body><div class="phishguard-wrapper">{self.email_selecionado_atual['html_completo']}</div></body></html>
        """
        
        self.area_texto_email.setHtml(html_responsivo)
        
        if chance_phishing >= limiar:
            self.banner_ia.setText(f"🚨 ALERTA PHISHING (Risco: {chance_phishing*100:.1f}%) | De: {remetente}")
            self.banner_ia.setStyleSheet("background-color: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #f85149; border-radius: 5px 5px 0 0; padding: 10px; font-size: 13px;")
        else:
            self.banner_ia.setText(f"✅ SEGURO (Risco: {chance_phishing*100:.1f}%) | De: {remetente}")
            self.banner_ia.setStyleSheet("background-color: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid #3fb950; border-radius: 5px 5px 0 0; padding: 10px; font-size: 13px;")

    def acao_responder(self):
        if not self.email_selecionado_atual: return
        
        dialogo = DialogoResposta(self.email_selecionado_atual['email_resposta'], self.email_selecionado_atual['assunto'], self)
        if dialogo.exec(): 
            texto_resposta = dialogo.obter_texto()
            if not texto_resposta:
                QMessageBox.warning(self, "Aviso", "A resposta não pode estar vazia.")
                return
            
            sucesso = enviar_resposta(self.email_selecionado_atual['email_resposta'], self.email_selecionado_atual['assunto'], texto_resposta)
            if sucesso: QMessageBox.information(self, "Enviado", "Sua resposta foi enviada com sucesso!")
            else: QMessageBox.critical(self, "Erro", "Falha ao enviar e-mail. Verifique sua conexão e credenciais SMTP.")

    def acao_lixeira(self):
        if not self.email_selecionado_atual: return
        
        resposta = QMessageBox.question(self, "Confirmar Exclusão", 
                                        "Mover este e-mail para a lixeira do servidor?\n(Esta ação será refletida no seu Gmail/Outlook).",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if resposta == QMessageBox.StandardButton.Yes:
            sucesso = mover_para_lixeira(self.email_selecionado_atual['uid'])
            if sucesso:
                linha_atual = self.lista_emails.currentRow()
                self.lista_emails.takeItem(linha_atual) 
                self.dados_emails.pop(linha_atual) 
                
                self.area_texto_email.setHtml("<html><body style='background-color: #ffffff;'></body></html>")
                self.banner_ia.setText("E-mail movido para a Lixeira com sucesso.")
                self.banner_ia.setStyleSheet("background-color: #30363d; color: #8b949e; border-radius: 5px 5px 0 0;")
                self.btn_responder.setEnabled(False)
                self.btn_lixeira.setEnabled(False)
            else:
                QMessageBox.critical(self, "Erro", "Falha ao mover para a lixeira. O servidor pode ter recusado o comando.")

    def fazer_logoff(self):
        self.input_senha.clear()
        self.lista_emails.clear()
        self.area_texto_email.setHtml("")
        self.banner_ia.setText("Selecione um e-mail para iniciar a varredura.")
        self.banner_ia.setStyleSheet("background-color: transparent;")
        self.stacked_principal.setCurrentIndex(0)

    def aplicar_estilo(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QLabel { color: #e6edf3; }
            
            #loginContainer { background-color: #161b22; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.05); }
            #titulo { color: #58a6ff; letter-spacing: 1px; margin-top: -10px;}
            #textoErro { color: #f85149; font-weight: bold; margin-top: 5px; }
            QLineEdit { background-color: #010409; color: #c9d1d9; border: 1px solid #30363d; border-radius: 8px; padding: 0 15px; font-size: 14px; }
            QLineEdit:focus { border: 2px solid #58a6ff; background-color: #0d1117; }
            
            #sidebar { background-color: #161b22; border-right: 1px solid #30363d; }
            #avatarUsuario { background-color: #1f6feb; color: white; border-radius: 20px; font-size: 18px; font-weight: bold; }
            #btnMenu { background-color: transparent; color: #c9d1d9; text-align: left; padding: 12px 15px; font-size: 14px; font-weight: bold; border-radius: 6px; border: none; }
            #btnMenu:hover { background-color: #21262d; color: #58a6ff; }
            #btnMenuSair { background-color: transparent; color: #f85149; text-align: left; padding: 12px 15px; font-size: 14px; font-weight: bold; border-radius: 6px; border: none; }
            #btnMenuSair:hover { background-color: rgba(248, 81, 73, 0.1); }
            
            #areaConteudo { background-color: #0d1117; }
            #btnAcao, #btnPrimario { background-color: #238636; color: white; font-weight: bold; border-radius: 6px; padding: 8px 15px; font-size: 14px; border: 1px solid rgba(240,246,252,0.1); }
            #btnAcao:hover, #btnPrimario:hover { background-color: #2ea043; border: 1px solid #3fb950; }
            
            #listaEmails { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; color: #c9d1d9; font-size: 13px; padding: 5px; }
            #listaEmails::item { padding: 15px; border-bottom: 1px solid #21262d; }
            #listaEmails::item:selected { background-color: #1f6feb; color: white; border-radius: 6px; }
            #areaLeitura { background-color: white; border: 1px solid #30363d; border-radius: 0 0 8px 8px; margin-top: 0px; }
            QSplitter::handle { background-color: #30363d; }

            #btnResponder { background-color: transparent; color: #58a6ff; font-weight: bold; border: 1px solid #58a6ff; border-radius: 5px; padding: 5px 15px; }
            #btnResponder:hover { background-color: rgba(88, 166, 255, 0.1); }
            #btnResponder:disabled { border: 1px solid #30363d; color: #8b949e; }
            
            #btnLixeira { background-color: transparent; color: #f85149; font-weight: bold; border: 1px solid #f85149; border-radius: 5px; padding: 5px 15px; }
            #btnLixeira:hover { background-color: rgba(248, 81, 73, 0.1); }
            #btnLixeira:disabled { border: 1px solid #30363d; color: #8b949e; }

            #inputArea { background-color: #010409; color: #c9d1d9; border: 1px solid #30363d; border-radius: 8px; padding: 15px; font-size: 14px; }
            #inputArea:focus { border: 1px solid #58a6ff; }
            QSlider::groove:horizontal { border: 1px solid #30363d; height: 8px; background: #010409; border-radius: 4px; }
            QSlider::sub-page:horizontal { background: #58a6ff; border-radius: 4px; }
            QSlider::handle:horizontal { background: white; border: 1px solid #30363d; width: 18px; margin-top: -5px; margin-bottom: -5px; border-radius: 9px; }
        """)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PhishGuardApp()
    window.show()
    sys.exit(app.exec())