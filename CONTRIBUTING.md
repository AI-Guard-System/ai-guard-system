# Contributing to react-ai-guard

We love your input! We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

1.  **Fork the repo** and create your branch from `main`.
2.  **Install dependencies**:
    ```bash
    npm install
    ```
3.  **Build the core package**:
    ```bash
    npm run build -w @ai-guard/core
    ```
4.  **Run tests**:
    ```bash
    npm test
    ```

## Monorepo Structure

This project is a monorepo managed by npm workspaces.

- **`packages/core`**: The core logic, including the Schema Engine and Web Workers. Zero React dependencies.
- **`packages/react`**: React hooks and components that consume the core package.
- **`packages/playground`**: A standalone Vite app for testing and demo purposes.

## Pull Request Process

1.  Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2.  Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, useful file locations and container parameters.
3.  Increase the version numbers in any examples files and the README.md to the new version that this Pull Request would represent. The versioning scheme we use is [SemVer](http://semver.org/).

## Coding Standards

- **Linting**: We use ESLint. Please ensure your code passes linting.
- **Testing**: We use Vitest. Add tests for any new features or bug fixes.
- **Formatting**: We use Prettier.
