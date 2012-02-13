import flask
import gpgme
import itertools
import re

try:
	from io import BytesIO
except ImportError:
	from StringIO import StringIO as BytesIO

app = flask.Flask(__name__)

ctx = gpgme.Context()
ctx.armor = True

search_re = re.compile("^0x", re.IGNORECASE)

def clean_search(s):
	"""
	Clean up the search parameter in /pks/lookup.
	Client is supposed to prefix key id/fpr with 0x,
	but we'll be liberal in what we accept.
	"""
	return str(search_re.sub('', s).upper())

op_re = re.compile("[^a-z]")

def clean_op(s):
	"""
	Clean up the op parameter in /pks/lookup.
	Prevent any potential funny business with magic Python attrs getting thru 
	the request.
	"""
	return op_re.sub('', s).lower()

class LookupOpHandler:
	"""
	Operations supported by the /pks/lookup endpoint.
	"""
	@staticmethod
	def get():
		"""
		The "get" operation

		The "get" operation requests keys from the keyserver.  A string that
		specifies which key(s) to return is provided in the "search"
		variable.

		The response to a successful "get" request is a HTTP document
		containing a keyring as specified in RFC-2440 [4], section 11.1, and
		ASCII armored as specified in section 6.2.

		The response may be wrapped in any HTML or other text desired, except
		that the actual key data consisting of an initial line break, the
		"-----BEGIN PGP PUBLIC KEY BLOCK-----" header, the armored key data
		itself, the "-----END PGP PUBLIC KEY BLOCK-----" header, and a final
		line break MUST NOT be modified from the form specified in [4].

		If no keys match the request, the keyserver should return an
		appropriate HTTP error code such as 404 ("Not Found").
   		"""
		search = flask.request.args.get('search', None)
		if search is None:
			resp = flask.make_response("Missing required search parameter", 500)
			return resp
		
		search = clean_search(search)
		
		# Require that the search term is a fingerprint/key id
		# (filter out fulltext matches against uid fields for this method).
		try:
			match = ctx.get_key(search)
		except gpgme.GpgmeError:
			match = None
		
		if match is None:
			return flask.make_response("No key matching search=%s" % (search), 404)
		
		keydata = BytesIO()
		ctx.export(search, keydata)
		
		if keydata:
			resp = flask.make_response(keydata.getvalue(), 200)
			resp.mimetype="text/plain"
			return resp
		
		return flask.make_response("No key matching search=%s" % (search), 404)
	
	@staticmethod
	def index():
		"""
		The "index" operation requests a list of keys on the keyserver that
		match the text or key ID in the "search" variable.  Historically, the
		"index" operation returned a human readable HTML document containing
		links for each found key, but this is not required.

		If the "index" operation is not supported, the keyserver should
		return an appropriate HTTP error code such as 501 ("Not
		Implemented").
   		"""
		search = flask.request.args.get('search', None)
		if search is None:
			resp = flask.make_response("Missing required argument: search", 400)
			return resp
		
		search = clean_search(search)
		
		if len(search) < 4:
			resp = flask.make_response("Search must be at least four characters", 500)
			return resp
		
		matches = []
		for k in ctx.keylist():
			match_uid = False
			for uid in k.uids:
				if search in uid.uid.upper():
					match_uid = True
					break
			
			for subkey in k.subkeys:
				if match_uid or search in subkey.fpr:
					matches.append(str(subkey.fpr))
		
		if matches:
			resp = flask.make_response("\n".join(matches), 200)
			resp.mimetype="text/plain"
			return resp
		
		return flask.make_response("No keys matching search request: %s" % (search), 404)
	
	@staticmethod
	def vindex():
		"""
		The "vindex" operation is similar to "index" in that it provides a
		list of keys on the keyserver that match the text of key ID in the
		"search" variable.  Historically, a "vindex" response was the same as
		"index" with the addition of showing the signatures on each key, but
		this is not required.

		If the "vindex" operation is not supported, the keyserver should
		return an appropriate HTTP error code such as 501 ("Not
		Implemented").
   		"""
		return flask.make_response("VIndex search not supported by this server.", 501)
	
@app.route("/pks/lookup")
def lookup():
	"""
	Keyserver requests are done via a HTTP GET URL that encodes the
	request within it.  Specifically, the abs_path (see [2], section
	3.2) is built up of the base request "/pks/lookup", followed by any
	variables.  Arguments are passed through the usual means as
	specified in [3], section 8.2.2.  The variables may be given in any
	order.  Keyservers MUST ignore any unknown variables.
	
	Modifiers not yet implemented: options, mr, nm, fingerprint, exact
	"""
	op = flask.request.args.get('op', None)
	op = clean_op(op)
	
	if op:
		handler = getattr(LookupOpHandler, op, None)
		if handler:
			return handler()
		
		return flask.make_response("Operation not supported: %s" % (op), 501)
	
	return flask.make_response("Missing required argument: op", 400)

@app.route("/pks/add", methods=['POST'])
def add():
	"""
	Keyserver submissions are done via a HTTP POST URL.  Specifically,
	the abs_path (see [2], section 3.2) is set to "/pks/add", and the key
	data is provided via HTTP POST as specified in [2], section 8.3, and
	[3], section 8.2.3.

	The body of the POST message contains a "keytext" variable which is
	set to an ASCII armored keyring as specified in [4], sections 6.2
	and 11.1.  The ASCII armored keyring should also be urlencoded as
	specified in [3], section 8.2.1.  Note that more than one key may
	be submitted in a single transaction.
	"""
	keytext = flask.request.form['keytext']
	try:
		keydata = BytesIO(str(keytext))
		result = ctx.import_(keydata)
		if result:
			resp_code = 200
			if result.imported:
				resp_code = 201
			return flask.make_response("Keys imported:\n%s" % 
									   "\n".join(k for k, _, _ in result.imports), resp_code)
	except UnicodeEncodeError, msg:
		return flask.make_response("Invalid characters in request: %s" % msg, 400)
	except gpgme.GpgmeError, err:
		_, _, msg = err
		return flask.make_response("GPGME: %s" % msg, 403)
	
	return flask.make_response("No keys were imported due to an unknown error", 404)

if __name__ == '__main__':
	app.run()

