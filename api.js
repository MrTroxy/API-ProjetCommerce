// Importation des modules nécessaires
const config = require('./config');
const secret = config.secret;
const express = require('express');
const mysql = require('mysql2');
const connexion = mysql.createConnection(config.connexionBD);
// Création de l'application Express
const application = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

// Configuration du serveur
application.set('port', process.env.PORT || 2222);

// Fonction pour la Vérification du token JWT
function verifierTokenJWT(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        console.log("Aucun token fourni")
        console.log(req.headers)
        return res.status(403).send({ message: "Aucun token fourni" });
    }

    jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
            console.log(err)
            console.log(token)
            return res.status(401).send({ message: "Accès non autorisé" });
        }
        req.userId = decoded.id;
        next();
    });
}
// Route pour l'authentification
application.use(bodyParser.urlencoded({ extended: false }));
application.post('/api/login', (req, res) => {
    const utilisateur = req.body.utilisateur;
    const password = req.body.password;

    // Vérification des informations de connexion (en interrogeant votre base de données)
    connexion.query('SELECT * FROM utilisateurs WHERE utilisateur = ? AND mot_de_passe = ?', [utilisateur, password], (erreur, resultats) =>
    {
        if (erreur)
        {
            console.log(erreur)
            reponse.status(500).send('Erreur lors de la récupération de l\'utilisateur');
        }
        else
        {
            if (resultats.length > 0) {
                const token = jwt.sign({ id: resultats[0].id }, config.secret, {
                    expiresIn: 86400 // expire dans 24 heures
                });
                console.log(resultats)
                console.log(token)
                res.json({
                    success: true,
                    message: 'Connexion réussie',
                    token: token
                });
            }
            else
            {
                console.log(resultats)
                res.status(401).json({
                    success: false,
                    message: 'Identifiant ou mot de passe incorrect'
                });
            }
        }
    });
});

// Lancement du serveur
application.listen
(
    application.get('port'), () =>
    {
        console.log('Serveur démarré sur le port ' + application.get('port'));
    }
);