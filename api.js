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
const bcrypt = require('bcrypt');

// Configuration du serveur
application.set('port', process.env.PORT || 2222);

// Fonction pour vérifier un mot de passe haché
async function verifierMotDePasse(motDePasse, hash)
{
    const match = await bcrypt.compare(motDePasse, hash);
    return match;
}


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
application.post('/api/connexion', async (req, res) => {
    const usager = req.body.usager;
    const mot_de_passe = req.body.mot_de_passe;

    // Vérification des informations de connexion (en interrogeant votre base de données)
    connexion.query('SELECT * FROM usagers WHERE usager = ?', [usager], async (erreur, resultats) =>
    {
        if (erreur)
        {
            console.log(erreur)
            res.status(500).send('Erreur lors de la récupération de l\'utilisateur');
        }
        else
        {
            if (resultats.length > 0) {
                // Vérification du mot de passe avec le hash enregistré dans la base de données
                const motDePasseValide = await verifierMotDePasse(mot_de_passe, resultats[0].mot_de_passe);

                if (motDePasseValide) {
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
                } else {
                    console.log(resultats)
                    res.status(401).json({
                        success: false,
                        message: 'Identifiant ou mot de passe incorrect'
                    });
                }
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

// Route pour l'ajout d'un produit dans la bd
application.use(bodyParser.json());
application.post('/api/ajouter/produit', verifierTokenJWT, async (req, res) => {
    const nom = req.body.nom;
    const description = req.body.description;
    const quantite = req.body.quantite;
    const prix = req.body.prix;

    // Vérification de la présence du champ nom
    if (!nom || !description || !quantite || !prix)
    {
        return res.status(400).send({ message: "Le nom, la description, la quantité et le prix sont obligatoires!" });
    }

    // Ajout de l'élément dans la base de données
    connexion.query('INSERT INTO produits (nom, description, quantite, prix) VALUES (?, ?, ?, ?)', [nom, description, quantite, prix], (erreur, resultats) => {
        if (erreur)
        {
            console.log(erreur);
            res.status(500).send('Erreur lors de l\'ajout de l\'élément');
        } else
        {
            res.status(201).send({ message: 'Produit ajouté avec succès', id: resultats.insertId });
        }
    });
});

// Route pour la suppression d'un produit dans la bd
application.post('/api/supprimer/produit', verifierTokenJWT, async (req, res) => {
    const id = req.body.id;

    // Vérification de la présence du champ id
    if (!id) {
        return res.status(400).send({ message: "Le champ id est manquant" });
    }

    // Suppression de l'élément dans la base de données
    connexion.query('DELETE FROM produits WHERE id = ?', [id], (erreur, resultats) => {
        if (erreur) {
            console.log(erreur);
            res.status(500).send('Erreur lors de la suppression de l\'élément');
        } else {
            if (resultats.affectedRows > 0) {
                res.status(200).send({ message: 'Produit supprimé avec succès', id: id });
            } else {
                res.status(404).send({ message: 'Aucun produit trouvé avec cet ID' });
            }
        }
    });
});

// Route pour obtenir l'ID du dernier produit ajouté
application.get('/api/produits/dernier', verifierTokenJWT, (req, res) => {
    connexion.query('SELECT * FROM produits ORDER BY id DESC LIMIT 1', (erreur, resultats) => {
        if (erreur) {
            console.log(erreur);
            res.status(500).send('Erreur lors de la récupération du dernier produit ajouté');
        } else {
            if (resultats.length > 0) {
                res.json({ id: resultats[0].id });
            } else {
                res.status(404).send('Aucun produit trouvé');
            }
        }
    });
});

// Route pour Obtenir la liste des produits disponibles dans la bd
application.get('/api/produits/obtenir', verifierTokenJWT, (requete, reponse) =>
{
    connexion.query('SELECT * FROM produits ORDER BY nom', (erreur, resultats) =>
    {
        if (erreur)
        {
            reponse.status(500).send('Erreur lors de la récupération de la liste des produits');
        } else {
            reponse.json(resultats);
        }
    });
});

// Route pour l'ajout d'un scan de jeton dans la bd
// Route pour ajouter un élément
application.use(bodyParser.json());
application.post('/api/ajouter/jeton', async (req, res) => {
    const numtag = req.body.numtag;
    const nom = req.body.nom;

    // Vérification de la présence du champ numtag et nom
    if (!numtag)
    {
        return res.status(400).send({ message: "Le champ numtag est manquant" });
    }
    if (!nom)
    {
        return res.status(400).send({ message: "Le champ nom est manquant" });
    }

    // Ajout de l'élément dans la base de données
    connexion.query('INSERT INTO jetons (numtag, nom) VALUES (?, ?)', [numtag, nom], (erreur, resultats) => {
        if (erreur)
        {
            console.log(erreur);
            res.status(500).send('Erreur lors de l\'ajout de l\'élément');
        } else
        {
            res.status(201).send({ message: 'Élément ajouté avec succès', id: resultats.insertId });
        }
    });
});

// Route qui permet d'obtenir la liste des jetons avec les heures :
application.get('/api/jetons/obtenir', verifierTokenJWT, (requete, reponse) =>
{
    console.log("Obtention jetons");
    connexion.query('SELECT * FROM jetons ORDER BY date DESC', (erreur, resultats) =>
    {
        if (erreur)
        {
            reponse.status(500).send('Erreur lors de la récupération de la liste des jetons');
            console.log("Obtention erreur");
        } else {
            console.log("Obtention success");
            reponse.json(resultats);
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