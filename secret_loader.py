import yaml
import hashlib
import sys

class Auth:
	'''
	Opens and returns a secrets file and holds auth info.
	'''
	secret_file = ''
	auth_hash = None

	def __init__(self, secret_path: str = 'secrets.yaml'):
		'''
		initialise this secrets file. I wanna make sure it can open so will raise an exception if it can't find the file
		'''
		self.secret_file = secret_path

		try:
			with open(secret_path, 'r') as secrets:
				auth_vars = yaml.safe_load(secrets)
		except FileNotFoundError:
			print(f'Could not load secrets file from {secret_path}')
		except Exception as e:
			print(f'something else went wrong wile loading the secrets file: {e}')


	def get_secrets(self):
		'''
		method to return the secret values as a dictionary, will also return the hashes
		'''
		auth_vars = None
		self.auth_hash = {}

		try:
			with open(self.secret_file, 'r') as secrets:
				auth_vars = yaml.safe_load(secrets)

			for item in auth_vars:
				self.auth_hash[item] = hashlib.sha256(auth_vars[item].encode()).hexdigest()

		except FileNotFoundError:
			print(f'Could not load secrets file from {self.secret_file}')
			self.auth_hash = None

		except Exception as e:
			print(f'something else went wrong wile loading the secrets file: {e}')
			self.auth_hash = None

		return {'hashes': self.auth_hash, 'values': auth_vars}

	def get_hashes(self):
		'''
		return the secret values as hashes only. Uses SHA256
		'''
		if self.auth_hash is not None:
			return self.auth_hash
		else:
			raise FileNotFoundError(f'There are no secrets loaded yet!')
