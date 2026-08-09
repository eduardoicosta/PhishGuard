"""
Gera programaticamente o dataset nativo PT-BR para treino offline do PhishGuard.

Uso:
    python scripts/gerar_dataset_ptbr.py
"""

import csv
import os
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "phishing_ptbr.csv")

# ---------------------------------------------------------------------------
# Label 0 — E-mails legítimos (corporativos, transacionais, informativos)
# ---------------------------------------------------------------------------

SEGUROS = [
    # Reuniões e agenda corporativa
    "Assunto: Reunião de alinhamento — Projeto Alpha\n\nOlá equipe,\n\nConfirmo nossa reunião de alinhamento amanhã às 10h na sala 3. Pauta: cronograma, riscos e próximos entregáveis.\n\nAtt,\nMariana — Gerente de Projetos",
    "Assunto: Convite: Daily stand-up\n\nBom dia,\n\nVocê foi convidado para a daily de segunda a sexta, das 9h15 às 9h30, via Microsoft Teams.\n\nOrganizador: TI Corporativa",
    "Assunto: Ata da reunião de 05/08\n\nPrezados,\n\nSegue em anexo a ata da reunião de status. Por favor, revisem os action items atribuídos a vocês até sexta-feira.\n\nAbraços,\nRicardo",
    "Assunto: Lembrete — 1:1 amanhã\n\nOi Eduardo,\n\nSó lembrando do nosso 1:1 amanhã às 14h. Se quiser incluir algum tema na pauta, me avise.\n\nValeu,\nCarla (RH)",
    "Assunto: Cancelamento de reunião\n\nPessoal,\n\nA reunião de hoje às 16h foi remarcada para quinta-feira, mesmo horário. Desculpem o inconveniente.\n\nAtenciosamente,\nPaulo",
    "Assunto: Workshop de segurança da informação\n\nColaboradores,\n\nInformamos que no dia 20/08 teremos workshop obrigatório sobre phishing e boas práticas digitais, das 15h às 17h.\n\nInscrições pelo portal interno.",
    "Assunto: Aprovação de férias\n\nOlá,\n\nSuas férias de 10 a 24 de setembro foram aprovadas pelo gestor. O RH registrará no sistema até amanhã.\n\nAtt,\nDepartamento Pessoal",
    "Assunto: Novo horário de expediente\n\nPrezados colaboradores,\n\nA partir de setembro, o expediente será das 8h30 às 17h30, mantendo a jornada de 8 horas.\n\nDiretoria",
    "Assunto: Pesquisa de clima organizacional\n\nOlá,\n\nConvidamos você a responder a pesquisa de clima até 15/08. Leva cerca de 5 minutos. Link interno: portal.empresa.com.br/clima\n\nObrigado,\nRH",
    "Assunto: Entrega de notebook — TI\n\nSeu equipamento está pronto para retirada na recepção do 4º andar, das 9h às 18h. Leve crachá e documento com foto.\n\nSuporte TI",
    # Dúvidas de clientes
    "Assunto: Dúvida sobre nota fiscal\n\nBoa tarde,\n\nRecebi o produto, mas a NF-e veio com CNPJ errado. Podem reemitir com o CNPJ 12.345.678/0001-90?\n\nObrigado,\nJoão Silva",
    "Assunto: Prazo de entrega\n\nOlá,\n\nGostaria de saber o prazo estimado para o pedido #45892, feito na semana passada.\n\nAtenciosamente,\nAna Paula",
    "Assunto: Solicitação de orçamento\n\nPrezados,\n\nPrecisamos de orçamento para 50 licenças do plano empresarial anual. Podem enviar proposta comercial?\n\nFelipe Mendes — Compras",
    "Assunto: Problema no acesso ao portal\n\nBom dia,\n\nNão consigo acessar o portal do cliente desde ontem. Aparece erro de senha, mas acabei de redefinir. Podem verificar?\n\nCarlos",
    "Assunto: Cancelamento de assinatura\n\nOlá,\n\nGostaria de cancelar minha assinatura mensal a partir do próximo ciclo. Meu e-mail cadastrado é cliente@email.com.\n\nGrato,\nLuciana",
    "Assunto: Troca de produto\n\nRecebi o tamanho errado da camiseta (pedi M, veio G). Como faço a troca? Número do pedido: 77821.\n\nMarcos",
    "Assunto: Segunda via de boleto\n\nBoa tarde,\n\nPerdi o boleto da mensalidade de julho. Podem enviar a segunda via?\n\nContrato: 00928374\n\nRenata",
    "Assunto: Agendamento de suporte técnico\n\nPreciso agendar visita técnica para instalação do roteador empresarial na filial de Campinas. Disponibilidade na próxima semana?\n\nTI — Grupo Nova",
    "Assunto: Feedback sobre atendimento\n\nOlá,\n\nQuero elogiar o atendimento da Ana no chat ontem. Resolveu meu problema rapidamente.\n\nObrigado,\nPedro",
    "Assunto: Atualização cadastral\n\nBom dia,\n\nMudamos de endereço. Novo CEP: 01310-100, Rua Augusta, 500, São Paulo. Podem atualizar no cadastro?\n\nEmpresa Beta Ltda",
    # Newsletters legítimas
    "Assunto: Newsletter TechBrasil — Edição de Agosto\n\nDestaques da semana: IA generativa no varejo, cases de cloud e entrevista com CTO da Nubank. Leia no site: techbrasil.com.br/newsletter\n\nDescadastre-se pelo link no rodapé.",
    "Assunto: Resumo semanal — Mercado Financeiro\n\nIbovespa +1,2%, dólar R$ 5,02, highlights de balanços. Análise completa no app InvestNews.\n\nVocê recebe porque assinou nossa newsletter.",
    "Assunto: Novidades da Comunidade Python Brasil\n\nConfira os slides das palestras da PythonBrasil 2026 e as vagas abertas no fórum. Acesse: python.org.br/comunidade\n\nEquipe PyBR",
    "Assunto: Seu digest semanal do LinkedIn\n\nVeja as 5 publicações mais relevantes da sua rede esta semana. Acesse linkedin.com/digest\n\nGerencie preferências nas configurações da conta.",
    "Assunto: Medium Daily Digest\n\nArtigos recomendados para você: 'Clean Architecture em Python' e 'Observabilidade com OpenTelemetry'.\n\nCancelar inscrição: medium.com/settings",
    "Assunto: Atualização de produto — Notion\n\nNovidade: templates de OKR e integração com Slack melhorada. Confira em notion.so/updates\n\nEquipe Notion",
    "Assunto: Coursera — Novos cursos recomendados\n\nCom base no seu histórico, selecionamos cursos de Data Science e ML. Veja em coursera.org/recommendations",
    "Assunto: GitHub Trending — Repositórios da semana\n\nProjetos em alta: ferramentas open source de observabilidade e frameworks web em Rust.\n\nGitHub Notifications",
    "Assunto: Spotify — Descubra novas playlists\n\nPlaylists feitas para você: Foco no Trabalho, Indie Brasil e Lo-Fi Beats.\n\nAbrir no app Spotify.",
    "Assunto: Resumo do seu time no Slack\n\n12 mensagens não lidas em #projeto-alpha, 3 menções em #geral. Abra o Slack para acompanhar.",
    # Comprovantes Uber / iFood
    "Assunto: Sua corrida Uber de hoje\n\nTotal: R$ 24,80\nOrigem: Av. Paulista, 1000\nDestino: Rua Oscar Freire, 200\nPagamento: Visa •••• 4821\n\nObrigado por viajar com a Uber.",
    "Assunto: Recibo da viagem Uber\n\nCorrida concluída em 08/08/2026 às 19:32.\nValor: R$ 18,50 | Motorista: Carlos | 4,9 estrelas\nBaixe o recibo no app.",
    "Assunto: Uber Eats — Pedido entregue\n\nSeu pedido #UE-928374 foi entregue.\nRestaurante: Sushi House\nTotal: R$ 67,90\nAvalie seu pedido no app.",
    "Assunto: iFood — Pedido confirmado\n\nPedido #IF-552910 confirmado pelo restaurante Burger & Co.\nPrevisão de entrega: 35-45 min.\nAcompanhe pelo app iFood.",
    "Assunto: iFood — Seu pedido saiu para entrega\n\nO entregador João está a caminho com seu pedido #IF-552910.\nPrevisão: 12 minutos.",
    "Assunto: Uber — Pagamento processado\n\nPagamento de R$ 32,10 aprovado no cartão Mastercard •••• 9012.\nViagem de 08/08/2026. Dúvidas? Acesse help.uber.com",
    "Assunto: Recibo iFood\n\nResumo do pedido: 2x Combo Executivo, 1x Refrigerante.\nSubtotal R$ 45,00 | Taxa de entrega R$ 6,99 | Total R$ 51,99\nObrigado!",
    "Assunto: Uber Pool — Viagem compartilhada\n\nValor final: R$ 14,20. Economia de R$ 8,00 em relação ao UberX.\nObrigado por usar Uber Pool.",
    "Assunto: iFood — Cashback disponível\n\nVocê ganhou R$ 5,00 de cashback no pedido de ontem. Válido até 30/08. Use no próximo pedido pelo app.",
    "Assunto: Uber — Atualização de tarifa\n\nSua corrida teve ajuste de tarifa dinâmica. Valor final: R$ 29,40. Detalhes no histórico do app.",
    # Notificações de redes sociais
    "Assunto: Instagram — Novo login detectado\n\nDetectamos um login na sua conta a partir de São Paulo, SP (dispositivo conhecido: iPhone). Se não foi você, acesse instagram.com/accounts/security",
    "Assunto: Facebook — Você tem 3 notificações\n\nMaria curtiu sua foto. Pedro comentou na sua publicação. Você foi marcado em um evento.\n\nVer no Facebook",
    "Assunto: Twitter/X — Menção em um post\n\n@dev_brasil mencionou você: 'Ótimo artigo sobre FastAPI!'.\n\nVer post | Configurar notificações",
    "Assunto: LinkedIn — 5 pessoas viram seu perfil\n\nVeja quem visitou seu perfil esta semana e atualize seu headline.\n\nAcessar LinkedIn",
    "Assunto: WhatsApp — Código de verificação (não compartilhe)\n\nSeu código: 482-910. Válido por 10 minutos. Não solicitamos este código por e-mail.",
    "Assunto: YouTube — Novo vídeo de canal inscrito\n\nCanal Tech em 10 publicou: 'Como configurar Docker no Windows'.\n\nAssistir no YouTube",
    "Assunto: TikTok — Seu vídeo atingiu 1.000 visualizações\n\nParabéns! Seu vídeo 'Receita de pão de queijo' passou de 1.000 views.\n\nVer estatísticas no app",
    "Assunto: Pinterest — Ideias para você\n\nNovos pins baseados nos seus interesses: decoração de home office e receitas veganas.\n\nAbrir Pinterest",
    "Assunto: Discord — Menção em #desenvolvimento\n\n@Eduardo foi mencionado por Ana: 'Consegue revisar o PR #142?'.\n\nAbrir Discord",
    "Assunto: Telegram — Login bem-sucedido\n\nNovo login no Telegram Desktop em Windows. IP: 189.xxx.xxx.xxx (São Paulo). Se não reconhece, encerre sessões em Configurações.",
    # Transacionais bancários legítimos (não phishing)
    "Assunto: Comprovante de transferência PIX\n\nTransferência realizada com sucesso.\nValor: R$ 150,00\nDestinatário: Maria Souza\nData: 08/08/2026 14:22\n\nBanco Inter — Não responda este e-mail.",
    "Assunto: Fatura do cartão disponível\n\nSua fatura com vencimento em 15/08 está disponível no app. Total: R$ 2.340,88.\n\nAcesse o app Bradesco Cartões. Não clicamos em links suspeitos.",
    "Assunto: Investimento — Rendimento mensal\n\nSeu CDB rendeu R$ 45,22 em julho. Consulte extrato completo no app da corretora.\n\nXP Investimentos",
    "Assunto: Pagamento de boleto confirmado\n\nRecebemos o pagamento do boleto de R$ 189,90 referente à conta de energia.\n\nEnel — Comprovante em anexo (PDF).",
    "Assunto: Extrato consolidado — Julho\n\nSeu extrato mensal está disponível no internet banking. Acesse pelo site oficial do banco digitando o endereço no navegador.",
    # E-mails internos diversos
    "Assunto: Boas-vindas ao time!\n\nOlá,\n\nSeja bem-vindo à equipe de Engenharia. Seu onboarding está agendado para segunda às 9h.\n\nPeople Ops",
    "Assunto: Lembrete: envio de timesheet\n\nPessoal,\n\nFavor lançar horas na ferramenta até sexta 18h. Dúvidas, falar com o PM.\n\nGestão de Projetos",
    "Assunto: Comunicado — Manutenção do VPN\n\nO VPN corporativo ficará indisponível domingo das 2h às 6h para manutenção.\n\nInfraestrutura",
    "Assunto: Parabéns pelo aniversário!\n\nA equipe deseja um feliz aniversário! Temos bolo na copa às 15h.\n\nRH",
    "Assunto: Documento compartilhado no Google Drive\n\nCarlos compartilhou 'Especificação v2.docx' com você. Acesse pelo Google Drive da empresa.",
]

# Variações adicionais para ampliar a base segura
SEGUROS_VARIACOES = [
    "Assunto: Confirmação de presença — Evento\n\nOlá,\n\nConfirmamos sua inscrição no evento '{evento}' no dia {dia}/08 às {hora}h.\n\nOrganização",
    "Assunto: Pedido #{pedido} — Em separação\n\nSeu pedido está sendo preparado para envio. Previsão de postagem: 2 dias úteis.\n\nLoja {loja}",
    "Assunto: Suporte — Ticket #{ticket} atualizado\n\nOlá {nome},\n\nAtualizamos seu chamado. Status: em análise. Responderemos em até 24h.\n\nEquipe de Suporte",
    "Assunto: Relatório mensual de vendas\n\nPrezado gestor,\n\nVendas de {mes}: R$ {valor}. Meta atingida em {pct}%.\n\nComercial",
    "Assunto: Convite para webinar\n\nParticipe do webinar '{tema}' dia {dia}/08 às {hora}h. Inscrição gratuita pelo site oficial da empresa.",
]

EVENTOS = ["Hackathon Interno", "All Hands Q3", "Treinamento LGPD", "Demo Day", "Happy Hour"]
LOJAS = ["Magazine Luiza", "Americanas", "Netshoes", "Casas Bahia", "Kabum"]
NOMES = ["Eduardo", "Ana", "Carlos", "Juliana", "Roberto", "Fernanda", "Lucas", "Patricia"]
MESES = ["junho", "julho", "agosto"]
TEMAS = ["Kubernetes na prática", "Liderança ágil", "Finanças pessoais", "Marketing digital"]

# ---------------------------------------------------------------------------
# Label 1 — Phishing clássico brasileiro
# ---------------------------------------------------------------------------

PHISHING = [
    # Itaú
    "Assunto: ITAU: Sua conta foi BLOQUEADA\n\nPrezado cliente,\n\nDetectamos acesso suspeito. CONFIRME seus dados em 24h ou sua conta será cancelada: http://itau-seguro-online.com/validar\n\nItaú Unibanco",
    "Assunto: Itaú — Atualização obrigatória de token\n\nSeu dispositivo de segurança expirou. Clique aqui para reativar: http://itau-token-secure.net/atualizar\n\nNão responda este e-mail.",
    "Assunto: URGENTE Itaú — Comprovante pendente\n\nTransação de R$ 4.890,00 aguarda confirmação. Cancele em: http://itau-cancelar-transacao.com\n\nCentral Itaú",
    "Assunto: Itaú — Pontos expirando HOJE\n\nSeus 45.000 pontos expiram hoje. Resgate em: http://itau-resgate-pontos.com\n\nPrograma de Relacionamento",
    "Assunto: Itaú informa: senha bloqueada\n\nSua senha de 4 dígitos foi bloqueada por segurança. Desbloqueie agora: http://itau-desbloqueio.net.br\n\nAtendimento Itaú",
    # Nubank
    "Assunto: Nubank — Conta temporariamente suspensa\n\nIdentificamos tentativa de acesso em outro dispositivo. Verifique sua identidade: http://nubank-verificar-conta.com\n\nEquipe Nubank",
    "Assunto: Nu: Seu cartão foi clonado\n\nCompra de R$ 2.999,00 em loja internacional. NÃO reconhece? Clique: http://nubank-contestar-compra.net\n\nNubank",
    "Assunto: Nubank — Cashback de R$ 500 esperando\n\nResgate seu cashback promocional antes que expire: http://nu-cashback-resgate.com\n\nPromoção Nubank",
    "Assunto: URGENTE Nu — Atualize seu cadastro\n\nSeus dados estão desatualizados. Atualize em 12h ou perderá acesso: http://nubank-atualizar-cadastro.org\n\nNubank",
    "Assunto: Nubank — Pix recebido de fonte desconhecida\n\nRecebeu R$ 3.500? Devolva em: http://nubank-devolucao-pix.com para evitar bloqueio.\n\nNu Pagamentos",
    # Caixa
    "Assunto: CAIXA — Benefício Bolsa Família\n\nSeu benefício está retido. Regularize seu CPF em: http://caixa-beneficio-regularizar.com\n\nCaixa Econômica Federal",
    "Assunto: Caixa — FGTS disponível para saque\n\nVocê tem R$ 8.432,00 de FGTS liberado. Solicite em: http://caixa-fgts-saque.net\n\nCaixa",
    "Assunto: Caixa Tem — Conta bloqueada\n\nSua conta Caixa Tem foi bloqueada por irregularidade. Desbloqueie: http://caixatem-desbloqueio.org\n\nCaixa Econômica",
    "Assunto: CAIXA URGENTE — Empréstimo pré-aprovado\n\nCrédito de R$ 15.000 pré-aprovado. Aceite em: http://caixa-credito-aprovado.com\n\nCaixa",
    "Assunto: Caixa — Atualização cadastral obrigatória\n\nPrazo final: hoje. Atualize em: http://caixa-atualizacao-cadastral.net\n\nLotéricas Caixa",
    # Correios — taxa alfândega
    "Assunto: Correios — Encomenda retida na alfândega\n\nSua encomenda AWB 847291BR aguarda pagamento de taxa de R$ 67,80. Pague em: http://correios-taxa-importacao.com\n\nCorreios Brasil",
    "Assunto: CORREIOS: Pacote internacional pendente\n\nPacote retido. Libere pagando taxa alfandegária: http://correios-rastreio-taxa.net/pagar\n\nMinistério da Fazenda",
    "Assunto: Correios — Último aviso antes de devolução\n\nEncomenda será devolvida em 48h se taxa não for paga: http://correios-pagamento-urgente.com\n\nCorreios",
    "Assunto: Rastreamento Correios — Taxa de despacho\n\nObjeto BR123456789BR retido. Quitação: http://correios-despacho-aduaneiro.org\n\nCorreios",
    "Assunto: Correios — Confirme endereço + taxa\n\nConfirme endereço e pague R$ 45,90: http://correios-confirmar-entrega.net\n\nCentral de Encomendas",
    # Milhas expirando
    "Assunto: Smiles — Suas milhas expiram AMANHÃ\n\n47.000 milhas expirando. Resgate agora: http://smiles-resgate-urgente.com\n\nGOL Smiles",
    "Assunto: LATAM Pass — Milhas a expirar\n\nSuas 32.500 milhas expiram em 24h. Use em: http://latampass-milhas-expirando.net\n\nLATAM Airlines",
    "Assunto: TudoAzul — Última chance de resgate\n\nMilhas expirando hoje! Resgate voos e produtos: http://tudoazul-resgate-milhas.com\n\nAzul Linhas Aéreas",
    "Assunto: Livelo — Pontos expirando\n\nSeus 28.000 pontos Livelo expiram esta semana. Troque em: http://livelo-pontos-expirando.org\n\nLivelo",
    "Assunto: Esfera — Resgate seus pontos\n\nPontos expirando! iPhone por 50% de desconto em pontos: http://esfera-resgate-promo.com\n\nEsfera Itaú",
    # Token / segurança
    "Assunto: Atualização de token de segurança — URGENTE\n\nSeu token digital expirou. Reative em 6h: http://token-seguranca-banco.com/reativar\n\nCentral de Segurança",
    "Assunto: Banco do Brasil — Dispositivo não reconhecido\n\nAcesso bloqueado. Valide seu dispositivo: http://bb-validar-dispositivo.net\n\nBB",
    "Assunto: Bradesco — Chave de segurança inválida\n\nSua chave expirou. Gere nova chave: http://bradesco-chave-seguranca.com\n\nBradesco",
    "Assunto: Santander — Confirme operação suspeita\n\nTransferência de R$ 5.600 pendente. Autorize ou cancele: http://santander-operacao-pendente.org\n\nSantander",
    "Assunto: Sicoob — Token SMS desatualizado\n\nAtualize token para continuar usando internet banking: http://sicoob-token-atualizar.com\n\nSicoob",
    # Golpes genéricos BR
    "Assunto: Receita Federal — CPF irregular\n\nSeu CPF será suspenso. Regularize em: http://receita-cpf-regularizar.net\n\nReceita Federal",
    "Assunto: DETRAN — Multa não paga\n\nMulta de R$ 293,47 com desconto de 50% hoje. Pague: http://detran-multa-desconto.com\n\nDETRAN-SP",
    "Assunto: Netflix — Pagamento recusado\n\nAtualize cartão em 24h ou perderá acesso: http://netflix-atualizar-pagamento.net\n\nNetflix",
    "Assunto: Mercado Livre — Compra não autorizada\n\nCompra de R$ 1.899 em seu nome. Conteste: http://mercadolivre-contestar.net\n\nMercado Livre",
    "Assunto: WhatsApp — Sua conta será desativada\n\nConfirme identidade em 12h: http://whatsapp-verificar-conta.com\n\nWhatsApp Inc.",
    "Assunto: Apple — iCloud armazenamento cheio\n\nSeus dados serão apagados. Compre armazenamento: http://apple-icloud-storage.net\n\nApple",
    "Assunto: Microsoft — Conta Outlook comprometida\n\nLogin suspeito detectado. Verifique: http://microsoft-outlook-seguro.org\n\nMicrosoft",
    "Assunto: PagSeguro — Saque pendente\n\nR$ 2.100 aguardando confirmação. Confirme: http://pagseguro-saque-pendente.com\n\nPagSeguro",
    "Assunto: PicPay — Cashback bloqueado\n\nLibere R$ 350 de cashback: http://picpay-liberar-cashback.net\n\nPicPay",
    "Assunto: Gov.br — Cadastro único desatualizado\n\nAtualize em 48h: http://govbr-atualizar-cadastro.com\n\nGoverno Federal",
]

PHISHING_VARIACOES = [
    "Assunto: {banco}: Conta bloqueada por segurança\n\nPrezado,\n\nAcesso suspeito detectado. Regularize em: http://{dominio}/validar\n\n{banco}",
    "Assunto: URGENTE — {banco} confirme sua identidade\n\nPrazo: 24 horas. Clique: http://{dominio}/confirmar\n\nCentral {banco}",
    "Assunto: {banco} — Transação de R$ {valor} pendente\n\nNão reconhece? Cancele: http://{dominio}/cancelar\n\n{banco}",
    "Assunto: {programa} — Milhas expirando em {horas}h\n\n{milhas} milhas serão perdidas. Resgate: http://{dominio}/resgate\n\n{programa}",
    "Assunto: Correios — Taxa alfandegária R$ {taxa}\n\nEncomenda {rastreio} retida. Pague: http://{dominio}/pagar\n\nCorreios",
    "Assunto: Token de segurança expirado — {banco}\n\nReative seu token: http://{dominio}/token\n\nSegurança Digital",
]

BANCOS = ["Itaú", "Nubank", "Caixa", "Bradesco", "Santander", "Banco do Brasil", "Inter", "C6 Bank"]
PROGRAMAS = ["Smiles", "LATAM Pass", "TudoAzul", "Livelo", "Esfera"]
DOMINIOS = [
    "banco-seguro-validar.com", "conta-verificar.net", "pix-seguro-online.org",
    "milhas-resgate-urgente.com", "correios-taxa-pagamento.net", "token-reativar-seguro.com",
    "nubank-verificacao.com", "itau-desbloqueio.net", "caixa-fgts-liberado.org",
]
RASTREIOS = ["BR847291BR", "BR123456789BR", "BR998877665BR", "BR554433221BR"]


def _gerar_variacoes_seguras() -> list[str]:
    exemplos = []
    for template in SEGUROS_VARIACOES:
        for _ in range(3):
            exemplos.append(
                template.format(
                    evento=random.choice(EVENTOS),
                    dia=random.randint(10, 28),
                    hora=random.choice(["9", "10", "14", "15", "16"]),
                    pedido=random.randint(10000, 99999),
                    loja=random.choice(LOJAS),
                    ticket=random.randint(1000, 9999),
                    nome=random.choice(NOMES),
                    mes=random.choice(MESES),
                    valor=f"{random.randint(50, 500)}.{random.randint(10, 99):02d}",
                    pct=random.randint(85, 120),
                    tema=random.choice(TEMAS),
                )
            )
    return exemplos


def _gerar_variacoes_phishing() -> list[str]:
    exemplos = []
    for template in PHISHING_VARIACOES:
        for _ in range(4):
            banco = random.choice(BANCOS)
            exemplos.append(
                template.format(
                    banco=banco,
                    dominio=random.choice(DOMINIOS),
                    valor=f"{random.randint(500, 9000)}.{random.randint(10, 99):02d}",
                    programa=random.choice(PROGRAMAS),
                    horas=random.choice([6, 12, 24, 48]),
                    milhas=random.randint(10000, 80000),
                    taxa=f"{random.randint(45, 120)}.{random.randint(10, 99):02d}",
                    rastreio=random.choice(RASTREIOS),
                )
            )
    return exemplos


def gerar_dataset() -> list[dict]:
    registros = []

    for texto in SEGUROS + _gerar_variacoes_seguras():
        registros.append({"texto": texto.strip(), "label": 0})

    for texto in PHISHING + _gerar_variacoes_phishing():
        registros.append({"texto": texto.strip(), "label": 1})

    random.seed(42)
    random.shuffle(registros)
    return registros


def salvar_csv(registros: list[dict], caminho: str) -> None:
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["texto", "label"])
        writer.writeheader()
        writer.writerows(registros)


def main() -> None:
    registros = gerar_dataset()
    salvar_csv(registros, OUTPUT_PATH)

    total = len(registros)
    seguros = sum(1 for r in registros if r["label"] == 0)
    phishing = sum(1 for r in registros if r["label"] == 1)

    print(f"Dataset gerado: {OUTPUT_PATH}")
    print(f"Total: {total} exemplos ({seguros} seguros, {phishing} phishing)")


if __name__ == "__main__":
    main()
