# nuclei configuration

Scanner settings are **not** files here: they live in scan policies in PostgreSQL
(`PolicyConfig`, docs/scan-policies.md) and are turned into command-line flags by the worker
adapter, so no free-form flags or config files can be injected through the API.
This directory is reserved for static tool configuration that must ship with the image.
