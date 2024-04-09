# Scan de redes com Suricata 

Uma vez que o Suricata esteja instalado e configurado, pode-se fazer detecções de diversos tipos de ataques de rede, mas este documento focará nos scans de rede, que podem ser feitos utilizando a ferramenta nmap.

## Conceitos

Existem dois tipos de scan de rede:

1. Scan Horizontal: Scan de um conjunto uma porta em vários ip's;
2. Scan Vertical: Scan de várias portas em um único ip.

Os ataques de scan de redes que foram analisados foram:

- *nmap -sS*: Procura promover o início de conexões TCP, enviando pacotes SYN, mas não dá continuidade a elas;
- *nmap -sT*: Procura a estabelcer diversas conexões TCP;
- *nmap -sU*: Envio de diversos pacotes UDP;

    - Os três ataques citados acima têm em comum o objetivo de verificar quais das portas analisadas estão abertas.

- *nmap -sA*: Procura obter informações diversas sobre a máquina analisada, como sistema operacional e versões de sistemas instalados;
- *nmap -sO*: Procura saber qual o sistema operacional da máquina que hospeda o ip analisado;
- *nmap -sX*: Procura saber quais portas estão abertas, enviando pacotes com flags PSH,FIN e URG, de modo a obter respostas específicas do alvo.

## Análise

Para detectar os scans de redes, foi ativado o conjunto de regras *emeging-scan.rules*, pertencente às regras *Emerging Threats*. Além disso, foram usadas regras presentes nos dois seguintes repositórios: 

1. [Regras criadas por Aleksi Bovellan](https://github.com/aleksibovellan/opnsense-suricata-nmaps/blob/main/local.rules);
2. [Regras de autoria própria](https://github.com/mayara-santos01/local.rules/blob/main/local.rules).

### *nmap -sT*
