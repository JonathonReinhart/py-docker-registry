from distutils.core import setup
setup(
    name = 'py-docker-registry',
    version = '0.0.1a0',
    install_requires = [
        'requests',
    ],

    py_modules = ['docker_registry'],
    scripts = ['docker-registry-console'],

    # Metadata
    author = 'Jonathon Reinhart',
    author_email = 'Jonathon.Reinhart@gmail.com',
    description = 'Python client for Docker Registry API',
    keywords = 'docker registry',
)
