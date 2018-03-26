import logging
R, B, Y, C, W = '\033[1;31m', '\033[1;37m', '\033[93m', '\033[1;30m', '\033[0m'
'''
class logger:
	def __init__ ( self ):
		return

	def __repr__ ( self ):
		return ''
'''

def set_logging():
	try:
		FORMAT = '%(message)s'
		LOG_LEVEL = logging.DEBUG

		# The basicConfig() method is used to change the configuration defaults
		logging.basicConfig ( level=LOG_LEVEL, format=FORMAT )

		# Associates level lvl with text levelName in an internal dictionary
		#logging.addLevelName( logging.WARNING, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
		# logging.addLevelName( logging.WARNING, "\033[1;31m[!]\033[1;0m" )
		#logging.addLevelName( logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))
		# logging.addLevelName( logging.ERROR,   "\033[1;41m[!]\033[1;0m" )
		

		# logging.warning( "dio" )
		# logging.error ( "cane" )
		
	except Exception:
		raise
