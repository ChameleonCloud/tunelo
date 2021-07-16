from oslo_context import context


class RequestContext(context.RequestContext):
    """Extends security contexts from the oslo.context library."""

    def ensure_thread_contain_context(self):
        """Ensure threading contains context
        For async/periodic tasks, the context of local thread is missing.
        Set it with request context and this is useful to log the request_id
        in log messages.
        """
        if context.get_current():
            return
        self.update_store()


def get_admin_context():
    """Create an administrator context."""
    context = RequestContext(
        auth_token=None, project_id=None, is_admin=True, overwrite=False
    )
    return context


def generate_request_id():
    return context.generate_request_id()
