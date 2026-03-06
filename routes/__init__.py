"""
routes/__init__.py
"""
from .auth         import register_auth
from .main         import register_main
from .exports      import register_exports
from .archive      import register_archive
from .admin_users  import register_admin_users
from .admin_rounds import register_admin_rounds
from .admin_core   import register_admin_core
from .admin_import import register_admin_import
# from .admin_api    import register_admin_api
from .pwa          import register_pwa
from .errors       import register_errors


def register_all_routes(app):
    register_auth(app)
    register_main(app)
    register_exports(app)
    register_archive(app)
    register_admin_users(app)
    register_admin_rounds(app)
    register_admin_core(app)
    register_admin_import(app)
    # register_admin_api(app)
    register_pwa(app)
    register_errors(app)
