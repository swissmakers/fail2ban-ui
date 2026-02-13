# Contributing

Thanks for contributing. This project is security-adjacent; changes should be deliberate and easy to review.

## Basic workflow

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feature/<name>
   ```

2. Make changes with well described commits. (Run formatting and basic checks.)

3. Open a pull request:

   * Describe what changed and why
   * Include screenshots for UI changes
   * Include migration notes if you changed configuration/DB behavior

## Coding and review expectations

* Prefer readable code over "clever code".
* Keep public-facing behavior documented (docs or inline help).
* Do not introduce new external network calls by default; make them opt-in where possible.
* For changes affecting auth or callback handling, include a short threat-model note in the PR description.

## Reporting security issues

If you believe you found a security issue, please do not open a public issue. Use a private disclosure channel appropriate for the project (for example, contact Swissmakers GmbH via website) and provide reproduction steps and impact assessment.