from http.server import HTTPServer, SimpleHTTPRequestHandler

class Handler(SimpleHTTPRequestHandler):
    def guess_type(self, path):
        if path.endswith('agent_details'):
            return 'text/html'
        return super().guess_type(path)

HTTPServer(('0.0.0.0', 8383), Handler).serve_forever()