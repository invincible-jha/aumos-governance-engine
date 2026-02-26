# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding from aumos-repo-template
- OPA Rego policy engine integration with REST API client
- Audit Wall architecture with separate PostgreSQL instance for immutable audit trail
- SOC 2, ISO 27001, HIPAA, ISO 42001, EU AI Act, and FedRAMP compliance workflows
- Policy-as-code CRUD API with version tracking and activation lifecycle
- Compliance dashboard aggregation endpoint
- Automated evidence collection framework
- Multi-regulation control mapping engine (RegulationMapperService)
- GovernanceEventPublisher for Kafka domain event publishing
- Docker Compose dev environment with postgres, postgres-audit, redis, kafka, and OPA
- CI/CD pipeline with lint, typecheck, test, docker build, and license checks
