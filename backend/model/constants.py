
FIREBASE_CERTIFICATE_PATH = 'credentials/secure-virtual-keyboard-firebase-credentials.json'
FIREBASE_API_KEY = 'AIzaSyADxfVJD1h3dsBKW1BLEkb5EehK5emnmzs'

# Debug option to show logs when run Unit Tests
# ALWAYS MAKE SURE THIS IS SET TO FALSE BEFORE ANY COMMIT
UNITTESTS_SHOW_LOGS = False

# Secret used on SHA256 hash that validates the JWT token
TOKEN_HASH_SECRET = b'0z6vhM9wj1wMP2G3i2ZNLf7PLv9bTqudfxn4Zw1UadXkUJ1PNI'

# Token Secret Key is used for signing the JWT token
TOKEN_SECRET_KEY = 'vamosficarricos'

# Token Algorithm is used for signing the JWT token
TEMP_TOKEN_ALGORITHM = 'HS384'
TOKEN_ALGORITHM = 'HS256'

# HMAC-based One-Time Password (HOTP) time-to-live is 10 minutes
HOTP_TTL = 600

# Token Expiration Time is used for signing the JWT token in seconds
TOKEN_EXPIRATION_TIME = 60 * 60

# Firebase User Fullname
USER_MODEL_FULLNAME_LENGTH_MAX = 32
USER_MODEL_FULLNAME_LENGTH_MIN = 4

# Firebase User Password
USER_MODEL_PASSWORD_LENGTH_MAX = 30
USER_MODEL_PASSWORD_LENGTH_MIN = 8
USER_MODEL_PASSWORD_REGEX = '^(?=.*[A-Z])(?=.*[!@#$&%*_-])(?=.*[0-9])(?=.*[a-z]).{8,}$'

# Firebase User Booleans
USER_MODEL_DISABLED_DEFAULT = False
USER_MODEL_EMAIL_VERIFIED_DEFAULT = False
USER_MODEL_OAUTHMFA_DEFAULT = False

# Firebase User Email
USER_MODEL_EMAIL_REGEX = '^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:.[a-zA-Z0-9-]+)*$'
