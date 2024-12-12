user_registration = {
    'responses': {
        200: {
            'description': 'User registered successfully or retrieved existing user',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'User registered successfully!'
                    },
                    'user': {
                        'type': 'object',
                        'properties': {
                            'user_id': {'type': 'integer'},
                            'username': {'type': 'string'},
                            'email': {'type': 'string'}
                        }
                    }
                }
            }
        },
        400: {
            'description': 'Error in registration',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
}

jwt_generation = {
    'responses': {
        200: {
            'description': 'JWT generated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'jwt': {'type': 'string'}
                }
            }
        }
    }
}

logout_response = {
    'responses': {
        202: {
            'description': 'User logged out successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string', 'example': 'Logged out'}
                }
            }
        }
    }
}

token_verification = {
    'responses': {
        200: {
            'description': 'Token verification successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'integer'},
                    'valid': {'type': 'boolean'}
                }
            }
        },
        401: {
            'description': 'Invalid or missing token',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
}

user_list_response = {
    'responses': {
        200: {
            'description': 'List of users retrieved successfully',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'user_id': {'type': 'integer'},
                        'username': {'type': 'string'},
                        'email': {'type': 'string'}
                    }
                }
            }
        }
    }
}

user_retrieval = {
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to retrieve'
        }
    ],
    'responses': {
        200: {
            'description': 'User retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'integer'},
                    'username': {'type': 'string'},
                    'email': {'type': 'string'}
                }
            }
        },
        404: {
            'description': 'User not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
}

user_update = {
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to update'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'email': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {
            'description': 'User updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'No data provided to update',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        }
    }
}

user_deletion = {
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'User deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'Error deleting user',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
}
