/**
 * Santé Cameroun - Backend MVP
 * Prototype d'application de diagnostic médical préliminaire
 * ⚠️ IMPORTANT: Ce système fournit des indications uniquement et ne remplace pas un médecin
 * Architecture conçue pour être divisée en micro-services ultérieurement
 */

// ==================== CONFIGURATION & IMPORTS ====================
import express, { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sante_cameroun_dev_secret_2024';
const SALT_ROUNDS = 10;

// Message d'avertissement médical constant
const MEDICAL_WARNING = '⚠️ Ce diagnostic est indicatif et ne remplace pas une consultation médicale.';

// ==================== MODÈLES & INTERFACES ====================
// FUTURE ÉVOLUTION: Ces interfaces seront dans des fichiers séparés (ex: models/user.model.ts)

interface User {
    id: string;
    email: string;
    password: string;
    name: string;
    phone?: string;
    region?: string;
    createdAt: Date;
}

interface SymptomInput {
    symptoms: string[];
    age?: number;
    region?: string;
    durationDays?: number;
}

interface DiseaseMatch {
    disease: string;
    probability: number;
    matchingSymptoms: string[];
    recommendedAction: string;
}

interface DiagnosticResult {
    matches: DiseaseMatch[];
    warning: string;
    timestamp: Date;
}

interface DiseaseInfo {
    id: string;
    name: string;
    description: string;
    commonSymptoms: string[];
    prevention: string[];
    naturalTreatments: string[];
    hospitalTreatments: string[];
    emergencySigns: string[];
}

interface QuizQuestion {
    id: string;
    question: string;
    options: string[];
    correctAnswer: number;
    explanation: string;
    category: 'prevention' | 'symptoms' | 'treatment';
}

// ==================== DONNÉES EN MÉMOIRE ====================
// FUTURE ÉVOLUTION: Ces données seront dans des bases de données séparées
// Auth Service: PostgreSQL/MySQL pour les utilisateurs
// Diagnostic Service: MongoDB/Redis pour les symptômes et maladies
// Content Service: CMS ou base de données pour les informations médicales

// Utilisateurs simulés (en production: base de données)
const users: User[] = [];

// Base de connaissances des maladies ciblées
const diseasesDatabase: DiseaseInfo[] = [
    {
        id: 'malaria',
        name: 'Paludisme',
        description: 'Maladie infectieuse transmise par les moustiques',
        commonSymptoms: ['fièvre', 'frissons', 'maux de tête', 'nausées', 'fatigue', 'douleurs musculaires'],
        prevention: [
            'Utiliser des moustiquaires imprégnées',
            'Porter des vêtements longs',
            'Utiliser des répulsifs',
            'Éliminer les eaux stagnantes'
        ],
        naturalTreatments: [
            'Repos abondant',
            'Hydratation régulière',
            'Consommation de feuilles de neem (sous supervision)'
        ],
        hospitalTreatments: [
            'Traitement par ACT (Thérapie Combinée à base d\'Artémisinine)',
            'Analgésiques pour la fièvre',
            'Surveillance des complications'
        ],
        emergencySigns: ['convulsions', 'conscience altérée', 'difficultés respiratoires', 'sang dans les urines']
    },
    {
        id: 'typhoid',
        name: 'Typhoïde',
        description: 'Infection bactérienne due à Salmonella typhi',
        commonSymptoms: ['fièvre élevée', 'maux de tête', 'douleurs abdominales', 'diarrhée ou constipation', 'perte d\'appétit'],
        prevention: [
            'Se laver les mains régulièrement',
            'Boire de l\'eau potable',
            'Bien cuire les aliments',
            'Éviter les aliments crus'
        ],
        naturalTreatments: [
            'Hydratation avec solutions de réhydratation',
            'Consommation de gingembre pour les nausées',
            'Repos complet'
        ],
        hospitalTreatments: [
            'Antibiotiques (ciprofloxacine, ceftriaxone)',
            'Réhydratation intraveineuse si nécessaire',
            'Antipyrétiques pour la fièvre'
        ],
        emergencySigns: ['saignements rectaux', 'vomissements persistants', 'confusion', 'fièvre très élevée']
    },
    {
        id: 'cholera',
        name: 'Choléra',
        description: 'Infection intestinale aiguë due à la bactérie Vibrio cholerae',
        commonSymptoms: ['diarrhée aqueuse abondante', 'vomissements', 'déshydratation rapide', 'crampes musculaires'],
        prevention: [
            'Utiliser de l\'eau traitée',
            'Bien laver les fruits et légumes',
            'Installations sanitaires adéquates',
            'Vaccination dans les zones à risque'
        ],
        naturalTreatments: [
            'Solution de réhydratation orale (eau, sel, sucre)',
            'Consommation d\'eau de coco',
            'Repos absolu'
        ],
        hospitalTreatments: [
            'Réhydratation intraveineuse massive',
            'Antibiotiques (doxycycline)',
            'Supplémentation en zinc pour les enfants'
        ],
        emergencySigns: ['déshydratation sévère', 'pouls faible', 'yeux creux', 'peau qui reste plissée']
    }
];

// Questions de quiz
const quizQuestions: QuizQuestion[] = [
    {
        id: 'q1',
        question: 'Quelle est la principale méthode de prévention du paludisme ?',
        options: [
            'Éviter les contacts physiques',
            'Utiliser des moustiquaires imprégnées',
            'Manger des aliments chauds',
            'Prendre des antibiotiques quotidiennement'
        ],
        correctAnswer: 1,
        explanation: 'Les moustiquaires imprégnées d\'insecticide sont la méthode la plus efficace pour prévenir les piqûres de moustiques nocturnes.',
        category: 'prevention'
    },
    {
        id: 'q2',
        question: 'Quel est le symptôme le plus caractéristique du choléra ?',
        options: [
            'Toux persistante',
            'Diarrhée aqueuse abondante',
            'Éruption cutanée',
            'Maux de gorge'
        ],
        correctAnswer: 1,
        explanation: 'Le choléra se caractérise par une diarrhée aqueuse très abondante qui peut mener à une déshydratation sévère en quelques heures.',
        category: 'symptoms'
    },
    {
        id: 'q3',
        question: 'Que faire en cas de suspicion de typhoïde ?',
        options: [
            'Prendre des médicaments sans ordonnance',
            'Consulter immédiatement un centre de santé',
            'Attendre que ça passe',
            'Manger des aliments épicés'
        ],
        correctAnswer: 1,
        explanation: 'La typhoïde nécessite un traitement antibiotique approprié et une surveillance médicale.',
        category: 'treatment'
    }
];

// ==================== SERVICES ====================
// FUTURE ÉVOLUTION: Chaque service sera un micro-service indépendant

/**
 * Service d'authentification
 * FUTURE: Devient auth-service avec sa propre base de données
 */
class AuthService {
    async register(email: string, password: string, name: string, phone?: string, region?: string): Promise<User> {
        // Validation basique
        if (!email || !password || !name) {
            throw new Error('Email, mot de passe et nom sont requis');
        }

        // Vérifier si l'utilisateur existe déjà
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            throw new Error('Un utilisateur avec cet email existe déjà');
        }

        // Hacher le mot de passe
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Créer l'utilisateur
        const user: User = {
            id: `user_${Date.now()}`,
            email,
            password: hashedPassword,
            name,
            phone,
            region,
            createdAt: new Date()
        };

        users.push(user);
        return { ...user, password: '' }; // Ne pas retourner le mot de passe
    }

    async login(email: string, password: string): Promise<string> {
        const user = users.find(u => u.email === email);
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            throw new Error('Mot de passe incorrect');
        }

        // Générer un JWT
        return jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
    }

    verifyToken(token: string): any {
        try {
            return jwt.verify(token, JWT_SECRET);
        } catch (error) {
            throw new Error('Token invalide');
        }
    }
}

/**
 * Service de diagnostic médical
 * FUTURE: Devient diagnostic-service avec IA/ML et base de connaissances élargie
 */
class DiagnosticService {
    analyzeSymptoms(input: SymptomInput): DiagnosticResult {
        const userSymptoms = input.symptoms.map(s => s.toLowerCase());
        const matches: DiseaseMatch[] = [];

        // Algorithme de correspondance simple
        // FUTURE: Remplacer par un modèle ML entraîné
        diseasesDatabase.forEach(disease => {
            const matchingSymptoms = disease.commonSymptoms.filter(symptom =>
                userSymptoms.includes(symptom.toLowerCase())
            );

            if (matchingSymptoms.length > 0) {
                const probability = Math.min(
                    (matchingSymptoms.length / disease.commonSymptoms.length) * 100,
                    85 // Plafond pour souligner le caractère indicatif
                );

                // Déterminer l'action recommandée
                let recommendedAction = 'Consulter un centre de santé pour évaluation';
                if (probability > 70) {
                    recommendedAction = 'Consulter URGEMENT un centre de santé';
                } else if (probability < 30) {
                    recommendedAction = 'Surveiller les symptômes et consulter si aggravation';
                }

                matches.push({
                    disease: disease.name,
                    probability: Math.round(probability),
                    matchingSymptoms,
                    recommendedAction
                });
            }
        });

        // Trier par probabilité décroissante
        matches.sort((a, b) => b.probability - a.probability);

        // Limiter à 3 résultats maximum
        const topMatches = matches.slice(0, 3);

        return {
            matches: topMatches,
            warning: MEDICAL_WARNING,
            timestamp: new Date()
        };
    }

    getAllDiseases(): DiseaseInfo[] {
        return diseasesDatabase.map(disease => ({
            ...disease,
            // FUTURE: Ajouter localisation/régionalisation des conseils
            prevention: [...disease.prevention, 'Consulter régulièrement un professionnel de santé']
        }));
    }

    getDiseaseById(id: string): DiseaseInfo | null {
        const disease = diseasesDatabase.find(d => d.id === id);
        return disease ? { ...disease } : null;
    }
}

/**
 * Service de contenu éducatif
 * FUTURE: Devient content-service avec CMS intégré
 */
class EducationService {
    getQuizQuestions(): { questions: QuizQuestion[], instructions: string } {
        return {
            questions: quizQuestions,
            instructions: 'Répondez aux questions pour tester vos connaissances. Ce quiz est à but éducatif uniquement.'
        };
    }

    calculateQuizScore(answers: { questionId: string, answerIndex: number }[]): {
        score: number,
        total: number,
        feedback: string
    } {
        let correct = 0;
        const results = [];

        for (const answer of answers) {
            const question = quizQuestions.find(q => q.id === answer.questionId);
            if (question && question.correctAnswer === answer.answerIndex) {
                correct++;
                results.push({ questionId: answer.questionId, correct: true, explanation: question.explanation });
            } else if (question) {
                results.push({ questionId: answer.questionId, correct: false, explanation: question.explanation });
            }
        }

        const score = (correct / quizQuestions.length) * 100;
        
        let feedback = 'Excellent! Vous avez une bonne connaissance des maladies. ';
        if (score < 50) {
            feedback = 'Consultez la section informations pour en savoir plus sur les maladies. ';
        } else if (score < 80) {
            feedback = 'Bon score! Poursuivez votre apprentissage. ';
        }

        return {
            score: Math.round(score),
            total: quizQuestions.length,
            feedback: feedback + MEDICAL_WARNING
        };
    }
}

// ==================== INSTANCES DES SERVICES ====================
const authService = new AuthService();
const diagnosticService = new DiagnosticService();
const educationService = new EducationService();

// ==================== MIDDLEWARES ====================
// FUTURE: Middlewares deviennent des packages partagés entre micro-services

const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            error: 'Token d\'authentification requis',
            warning: MEDICAL_WARNING
        });
    }

    try {
        const user = authService.verifyToken(token);
        (req as any).user = user;
        next();
    } catch (error) {
        return res.status(403).json({ 
            error: 'Token invalide ou expiré',
            warning: MEDICAL_WARNING
        });
    }
};

const validateDiagnosticInput = (req: Request, res: Response, next: NextFunction) => {
    const { symptoms } = req.body;
    
    if (!symptoms || !Array.isArray(symptoms) || symptoms.length === 0) {
        return res.status(400).json({
            error: 'La liste des symptômes est requise',
            example: { symptoms: ['fièvre', 'maux de tête'] },
            warning: MEDICAL_WARNING
        });
    }

    if (symptoms.length > 10) {
        return res.status(400).json({
            error: 'Maximum 10 symptômes autorisés',
            warning: MEDICAL_WARNING
        });
    }

    next();
};

// ==================== CONTRÔLEURS ====================
// FUTURE: Chaque contrôleur devient un endpoint dans un micro-service spécifique

class AuthController {
    async register(req: Request, res: Response) {
        try {
            const { email, password, name, phone, region } = req.body;
            
            const user = await authService.register(email, password, name, phone, region);
            
            // Générer un token directement après l'inscription
            const token = await authService.login(email, password);
            
            res.status(201).json({
                message: 'Inscription réussie',
                user: { id: user.id, email: user.email, name: user.name, region: user.region },
                token,
                warning: MEDICAL_WARNING
            });
        } catch (error: any) {
            res.status(400).json({
                error: error.message,
                warning: MEDICAL_WARNING
            });
        }
    }

    async login(req: Request, res: Response) {
        try {
            const { email, password } = req.body;
            
            if (!email || !password) {
                return res.status(400).json({
                    error: 'Email et mot de passe requis',
                    warning: MEDICAL_WARNING
                });
            }

            const token = await authService.login(email, password);
            
            res.json({
                message: 'Connexion réussie',
                token,
                warning: MEDICAL_WARNING
            });
        } catch (error: any) {
            res.status(401).json({
                error: error.message,
                warning: MEDICAL_WARNING
            });
        }
    }
}

class DiagnosticController {
    async analyze(req: Request, res: Response) {
        try {
            const input: SymptomInput = {
                symptoms: req.body.symptoms,
                age: req.body.age,
                region: req.body.region,
                durationDays: req.body.durationDays
            };

            // FUTURE: Ajouter journalisation des diagnostics pour analyse
            const result = diagnosticService.analyzeSymptoms(input);
            
            res.json({
                ...result,
                note: 'Ce résultat est basé sur un algorithme simple et nécessite validation médicale'
            });
        } catch (error: any) {
            res.status(500).json({
                error: 'Erreur lors de l\'analyse',
                details: error.message,
                warning: MEDICAL_WARNING
            });
        }
    }

    async getAllDiseases(req: Request, res: Response) {
        try {
            const diseases = diagnosticService.getAllDiseases();
            
            res.json({
                diseases,
                count: diseases.length,
                warning: MEDICAL_WARNING,
                note: 'Informations à but éducatif uniquement'
            });
        } catch (error: any) {
            res.status(500).json({
                error: 'Erreur lors de la récupération des informations',
                warning: MEDICAL_WARNING
            });
        }
    }

    async getDiseaseById(req: Request, res: Response) {
        try {
            const { id } = req.params;
            const disease = diagnosticService.getDiseaseById(id as string );
            
            if (!disease) {
                return res.status(404).json({
                    error: 'Maladie non trouvée',
                    availableDiseases: diseasesDatabase.map(d => ({ id: d.id, name: d.name })),
                    warning: MEDICAL_WARNING
                });
            }
            
            res.json({
                disease,
                warning: MEDICAL_WARNING,
                emergencyAdvice: 'En cas de signes d\'urgence, contactez immédiatement le 1410 (Samu Cameroun)'
            });
        } catch (error: any) {
            res.status(500).json({
                error: 'Erreur lors de la récupération',
                warning: MEDICAL_WARNING
            });
        }
    }
}

class EducationController {
    async getQuiz(req: Request, res: Response) {
        try {
            const quiz = educationService.getQuizQuestions();
            
            res.json({
                ...quiz,
                warning: MEDICAL_WARNING,
                purpose: 'Ce quiz vise à améliorer la sensibilisation aux maladies courantes'
            });
        } catch (error: any) {
            res.status(500).json({
                error: 'Erreur lors de la récupération du quiz',
                warning: MEDICAL_WARNING
            });
        }
    }

    async submitQuiz(req: Request, res: Response) {
        try {
            const { answers } = req.body;
            
            if (!Array.isArray(answers)) {
                return res.status(400).json({
                    error: 'Format des réponses invalide',
                    warning: MEDICAL_WARNING
                });
            }

            const result = educationService.calculateQuizScore(answers);
            
            res.json({
                ...result,
                recommendation: 'Consultez régulièrement la section informations pour mettre à jour vos connaissances',
                warning: MEDICAL_WARNING
            });
        } catch (error: any) {
            res.status(500).json({
                error: 'Erreur lors du calcul du score',
                warning: MEDICAL_WARNING
            });
        }
    }
}

// ==================== INSTANCES DES CONTRÔLEURS ====================
const authController = new AuthController();
const diagnosticController = new DiagnosticController();
const educationController = new EducationController();

// ==================== ROUTES ====================
// FUTURE: Routes deviennent des endpoints API Gateway devant les micro-services

// Routes publiques
app.post('/api/auth/register', authController.register.bind(authController));
app.post('/api/auth/login', authController.login.bind(authController));
app.get('/api/diseases', diagnosticController.getAllDiseases.bind(diagnosticController));
app.get('/api/diseases/:id', diagnosticController.getDiseaseById.bind(diagnosticController));
app.get('/api/quiz', educationController.getQuiz.bind(educationController));

// Routes protégées (nécessitent authentification)
app.post('/api/diagnostic', authenticateToken, validateDiagnosticInput, diagnosticController.analyze.bind(diagnosticController));
app.post('/api/quiz/submit', authenticateToken, educationController.submitQuiz.bind(educationController));

// Route de santé
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'Santé Cameroun API',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        warning: MEDICAL_WARNING
    });
});

// Route racine
app.get('/', (req, res) => {
    res.json({
        message: 'API Santé Cameroun - Prototype de diagnostic médical préliminaire',
        version: '1.0.0',
        endpoints: {
            auth: ['POST /api/auth/register', 'POST /api/auth/login'],
            diagnostic: ['POST /api/diagnostic (authentifié)'],
            diseases: ['GET /api/diseases', 'GET /api/diseases/:id'],
            quiz: ['GET /api/quiz', 'POST /api/quiz/submit (authentifié)']
        },
        warning: MEDICAL_WARNING,
        important: 'CE SYSTÈME NE REMPLACE PAS UN MÉDECIN. CONSULTEZ TOUJOURS UN PROFESSIONNEL DE SANTÉ.'
    });
});

// Gestion des erreurs 404
app.use((req: Request, res: Response) => {
    res.status(404).json({
        error: 'Endpoint non trouvé',
        availableEndpoints: ['/api/auth/register', '/api/auth/login', '/api/diagnostic', '/api/diseases', '/api/quiz', '/api/health'],
        warning: MEDICAL_WARNING
    });
});

// Gestion globale des erreurs
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
    console.error('Erreur globale:', error);
    
    res.status(500).json({
        error: 'Erreur interne du serveur',
        message: process.env.NODE_ENV === 'development' ? error.message : undefined,
        warning: MEDICAL_WARNING,
        emergencyContact: 'Contactez le 1410 en cas d\'urgence médicale'
    });
});

// ==================== DÉMARRAGE DU SERVEUR ====================
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`
        ============================================
        Santé Cameroun API - Prototype
        ============================================
        Serveur démarré sur le port ${PORT}
        Mode: ${process.env.NODE_ENV || 'development'}
        
        Points de terminaison disponibles:
        - POST /api/auth/register
        - POST /api/auth/login
        - POST /api/diagnostic (authentifié)
        - GET  /api/diseases
        - GET  /api/diseases/:id
        - GET  /api/quiz
        - POST /api/quiz/submit (authentifié)
        - GET  /api/health
        
        IMPORTANT: ${MEDICAL_WARNING}
        ============================================
        `);
    });
}

export default app;

// ==================== EXEMPLES DE REQUÊTES HTTP ====================
/*
EXEMPLE 1: Inscription
POST http://localhost:3000/api/auth/register
Content-Type: application/json

{
    "email": "utilisateur@example.com",
    "password": "MotDePasse123",
    "name": "Jean Dupont",
    "phone": "+237 6XXXXXXXX",
    "region": "Littoral"
}

EXEMPLE 2: Connexion
POST http://localhost:3000/api/auth/login
Content-Type: application/json

{
    "email": "utilisateur@example.com",
    "password": "MotDePasse123"
}

EXEMPLE 3: Diagnostic (avec token)
POST http://localhost:3000/api/diagnostic
Authorization: Bearer <VOTRE_TOKEN_JWT>
Content-Type: application/json

{
    "symptoms": ["fièvre", "maux de tête", "nausées"],
    "age": 30,
    "region": "Centre",
    "durationDays": 2
}

EXEMPLE 4: Liste des maladies
GET http://localhost:3000/api/diseases

EXEMPLE 5: Quiz
GET http://localhost:3000/api/quiz

EXEMPLE 6: Soumission du quiz
POST http://localhost:3000/api/quiz/submit
Authorization: Bearer <VOTRE_TOKEN_JWT>
Content-Type: application/json

{
    "answers": [
        {"questionId": "q1", "answerIndex": 1},
        {"questionId": "q2", "answerIndex": 1},
        {"questionId": "q3", "answerIndex": 1}
    ]
}
*/

// ==================== NOTES POUR L'ÉVOLUTION FUTURE ====================
/*
ARCHITECTURE MICRO-SERVICES RECOMMANDÉE:

1. AUTH-SERVICE (service d'authentification)
   - Gestion des utilisateurs
   - JWT generation/validation
   - Base: PostgreSQL avec table users
   - Port: 3001

2. DIAGNOSTIC-SERVICE (service de diagnostic)
   - Analyse des symptômes
   - Base de connaissances des maladies
   - Base: MongoDB pour flexibilité des schémas
   - Port: 3002
   - Communication: RabbitMQ/Kafka pour les événements

3. CONTENT-SERVICE (service de contenu)
   - Informations sur les maladies
   - Quiz éducatifs
   - Articles de sensibilisation
   - Base: PostgreSQL + Redis pour le cache
   - Port: 3003

4. API-GATEWAY (point d'entrée unique)
   - Routing vers les micro-services
   - Rate limiting
   - Logging centralisé
   - Port: 3000 (public)

5. NOTIFICATION-SERVICE (service de notifications)
   - Rappels de consultations
   - Alertes sanitaires
   - SMS/Email (Twilio, SendGrid)

COMMENT DÉCOUPER CE FICHIER:

1. Créer un répertoire pour chaque service
2. Extraire les interfaces dans shared/types/
3. Créer un package shared pour les utilitaires communs
4. Configurer Docker pour chaque service
5. Implémenter Docker Compose pour le développement
6. Ajouter Kubernetes pour la production

BASE DE DONNÉES EN PRODUCTION:
- Auth: PostgreSQL avec chiffrement des mots de passe
- Diagnostic: MongoDB Atlas avec index géospatial
- Cache: Redis pour les résultats fréquents
- Logs: Elasticsearch + Kibana

SÉCURITÉ À AJOUTER:
- HTTPS/TLS
- Rate limiting par IP
- Validation des inputs avancée
- Audit logs pour les diagnostics
- Chiffrement des données sensibles
*/

console.log(`\n📋 NOTES D'IMPLÉMENTATION:
1. Pour tester: npm install express jsonwebtoken bcrypt @types/express @types/jsonwebtoken @types/bcrypt typescript ts-node
2. Compiler: npx tsc server.ts --outDir dist --module commonjs --target es2020
3. Démarrer: node dist/server.js
4. Variables d'environnement recommandées:
   - JWT_SECRET=une_clé_secrète_complexe
   - NODE_ENV=production
   - PORT=3000

⚠️  AVERTISSEMENT FINAL: Ce prototype est à but éducatif. 
Pour une utilisation réelle, consultez des médecins et des 
experts en santé publique camerounais pour valider les informations.
`);