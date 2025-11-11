
# Ontology-driven threat modelling (OdTM) framework

Ontology-driven Threat Modelling (OdTM) framework is a set of means for implementation 
of an ontological approach into automatic threat modelling of computer systems.


The ontological approach, provided by the OdTM framework, has two general benefits.
Firstly, it enables formalization of security related knowledge 
(architectual components and associated threats and countermeasures)
of different computer system types (architectural domains) in form of domain-specific threat models 
(ontologies).
Secondly, after a system architect has described a computer system in terms 
of a domain-specific model, for example, with DFD (Data Flow Diagram), 
it allows the use of automatic reasoning procedures to build a threat model of the system 
(i.e. figure out relevant threats and countermeasures).

To start using the OdTM framework, you can read [this guide](guide/README.md).


Our approach is based on a [base threat model (ontology)](docs/BASEMODEL.md).
The base model enables creation of various domain-specific threat models 
and their integration with external sources, like attack/vulnerability/weakness enumerations, 
also with catalogues of traditional security (threat) patterns.

We also have implementation of 
[Academic Cloud Computing Threat Patterns (ACCTP)](docs/ODTMACCTP.md) model as a domain-specific threat model
and [Integrated model of ATT&CK, CAPEC, and CWE](docs/IM.md).

All the models are implemented as OWL (Web Ontology Language) ontologies with Description Logics (DLs) as a mathematical background.

We have created [a set of semantic data flow diagrams](https://github.com/nets4geeks/DockerComposeDataset) (OWL, RDF) from real cloud application configurations that can be used for various research in the threat modeling field.

The framework includes different [software tools](applications/OdTMServer/) for automation of the threat modelling process
(in particular, an alternative threat rule engine).

The applications are built with Java, 
the [OWL API](https://github.com/owlcs/owlapi) 
and [HermiT Reasoner](http://www.hermit-reasoner.com/) libraries.

If you want to refer to OdTM, please, read [this article](https://www.researchgate.net/profile/Andrei-Brazhuk/publication/397190137_Automatic_analysis_of_containerized_application_deployment_models_based_on_ontologies_and_knowledge_graphs/links/69083e5c368b49329fa8edba/Automatic-analysis-of-containerized-application-deployment-models-based-on-ontologies-and-knowledge-graphs.pdf)
and cite it:O4>Brazhuk A. Automatic analysis of containerized application deployment models based on ontologies and knowledge graphs //International Journal of Open Information Technologies. – 2025. – Т. 13. – N. 11. – С. 105-111.

## Base Threat Model

* [OWL file](OdTMBaseThreatModel.owl)
* [Description](docs/BASEMODEL.md)
* [Changelog](docs/BASEMODEL_changelog.md)

## Domain-specific threat models

* [A set of semantic data flow diagrams](https://github.com/nets4geeks/DockerComposeDataset)
* [Integrated model of ATT&CK, CAPEC, and CWE](docs/IM.md)
* [Academic Cloud Computing Threat Patterns (ACCTP) model](docs/ODTMACCTP.md)
* [Common Cloud Computing Threat Model or CCCTM](docs/ODTMCCCTM.md) (obsolete)

## Applications

* [OdTM Server](applications/OdTMServer/)
* [Docker compose parser](applications/parseDockerCompose/)
* [Parser of security enumerations](applications/generateIM/)
* [Check application](applications/checkApplication/)
