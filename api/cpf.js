export default async function handler(req, res) {
    const { cpf } = req.query;
    if (!cpf) return res.status(400).json({ success: false, error: 'CPF não fornecido' });

    // Puxa a chave das variáveis de ambiente configuradas no painel da Vercel
    const apiKey = process.env.CPFHUB_API_KEY;
    if (!apiKey) return res.status(500).json({ success: false, error: 'Chave da API não configurada no servidor' });

    try {
        const response = await fetch(`https://api.cpfhub.io/cpf/${cpf}`, {
            method: 'GET',
            headers: { 'x-api-key': apiKey, 'Accept': 'application/json' }
        });
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ success: false, error: data.message || 'Erro na API' });
        return res.status(200).json({ success: true, data: data });
    } catch (error) {
        return res.status(500).json({ success: false, error: 'Falha ao conectar com a CPFHub' });
    }
}
