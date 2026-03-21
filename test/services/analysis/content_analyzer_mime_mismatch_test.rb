require "test_helper"

class Analysis::ContentAnalyzerMimeMismatchTest < ActiveSupport::TestCase
  test "detects divergent text/plain and text/html as mime mismatch" do
    email = create(:email,
      body_text: "Prezado cliente, sua conta bancária foi verificada com sucesso. " \
                 "Domínio registrado há 7 anos, Alexa rank 15000, CNPJ válido. " \
                 "Empresa legítima de tecnologia com sede em São Paulo. " \
                 "Nenhuma ação necessária da sua parte, obrigado pela confiança.",
      body_html: "<html><body>" \
                 "<p>URGENTE: Seu cartão foi clonado! Clique aqui para baixar nosso " \
                 "app de proteção e insira seu CPF, senha do banco e número do cartão " \
                 "para verificação imediata. Não perca tempo ou sua conta será bloqueada! " \
                 "Download: http://app-malicioso.com/instalar.apk</p>" \
                 "</body></html>",
      extracted_urls: ["http://app-malicioso.com/instalar.apk"]
    )

    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.details["mime_mismatch_detected"], "Should detect MIME mismatch"
    assert layer.details["mime_similarity"] < 30, "Similarity should be below 30%"
    assert layer.score > 0, "Score should be boosted"
    assert_match(/Divergência significativa/, layer.explanation)
  end

  test "does not flag matching text/plain and text/html" do
    content = "Olá, gostaria de saber mais sobre os serviços de consultoria " \
              "da empresa. Meu nome é João Silva e trabalho na área de TI. " \
              "Podemos agendar uma reunião para a próxima semana?"
    email = create(:email,
      body_text: content,
      body_html: "<html><body><p>#{content}</p></body></html>",
      extracted_urls: []
    )

    layer = Analysis::ContentAnalyzer.new(email).analyze

    refute layer.details["mime_mismatch_detected"], "Should not flag matching content"
  end

  test "does not flag when text/plain is too short" do
    email = create(:email,
      body_text: "Short text",
      body_html: "<html><body><p>This is a completely different and much longer HTML body " \
                 "that has nothing to do with the text/plain part at all.</p></body></html>",
      extracted_urls: []
    )

    layer = Analysis::ContentAnalyzer.new(email).analyze

    refute layer.details["mime_mismatch_detected"], "Should skip short text/plain"
  end

  test "does not flag when body_html is blank" do
    email = create(:email,
      body_text: "This is a normal email body with enough content to be analyzed " \
                 "by the mime mismatch detector and should not trigger any alarm.",
      body_html: nil,
      extracted_urls: []
    )

    layer = Analysis::ContentAnalyzer.new(email).analyze

    refute layer.details["mime_mismatch_detected"], "Should skip when no HTML"
  end
end
