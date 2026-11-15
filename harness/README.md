# Harness

Starts the aerie container image for the commit under test (`ghcr.io/synssins/aerie:<commit>`), waits for its health check, seeds it through aerie's own API (spaces, pages, users, groups, tokens and an OAuth client), and hands the base address and credentials to the suites. To write: `docker-compose.yml` and the seeding script.
