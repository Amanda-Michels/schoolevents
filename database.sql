DROP DATABASE IF EXISTS SchoolEvents;
CREATE DATABASE SchoolEvents;
USE SchoolEvents;

CREATE TABLE Utilizador 
(
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    email               VARCHAR(100) UNIQUE NOT NULL,
    google_id           VARCHAR(255),
    senha_hash          VARCHAR(255) DEFAULT NULL,

    auth_provider ENUM('local','google','ambos') DEFAULT 'local',
    tipo_utilizador ENUM('aluno', 'professor', 'admin') NOT NULL
);

CREATE TABLE ProjetosEscolares 
(
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    titulo_proj         VARCHAR(255) NOT NULL,
    descricao_proj      TEXT,
    data_proj           DATE,
    horario_proj        TIME,
    local_proj          VARCHAR(255),
    professor_id        INT,
    estado              VARCHAR(20) DEFAULT 'pendente',

    CONSTRAINT fk_projetos_professor FOREIGN KEY (professor_id) 
    REFERENCES Utilizador(id) ON DELETE SET NULL
);

CREATE TABLE Inscricoes 
(
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    aluno_id            INT NOT NULL,
    projeto_id          INT NOT NULL,
    data_inscricao      DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_inscricoes_aluno FOREIGN KEY (aluno_id)
    REFERENCES Utilizador(id) ON DELETE CASCADE,

    CONSTRAINT fk_inscricoes_projeto FOREIGN KEY (projeto_id)
    REFERENCES ProjetosEscolares(id) ON DELETE CASCADE,

    CONSTRAINT unique_inscricao UNIQUE (projeto_id, aluno_id)
);

CREATE TABLE Duvidas 
(
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    projeto_id          INT NOT NULL,
    aluno_id            INT NOT NULL,
    pergunta            TEXT NOT NULL,
    resposta            TEXT DEFAULT NULL,
    data_envio          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_duvidas_projeto FOREIGN KEY (projeto_id)
    REFERENCES ProjetosEscolares(id) ON DELETE CASCADE,

    CONSTRAINT fk_duvidas_aluno FOREIGN KEY (aluno_id)
    REFERENCES Utilizador(id) ON DELETE CASCADE
);


INSERT INTO Utilizador (email, senha_hash, auth_provider, tipo_utilizador)
VALUES 
(
    'schooleventsadm@gmail.com',
    'scrypt:32768:8:1$EprWQUM4ALwTSxjc$3277fc4352fd78336078635768c377e527c654904d1769dcdc0f4333450730d1a1433ef4222a905e81415ebc7b547f7f321413f80898687766db51cc23204f0e',
    'local','admin'
);