import OAuth from '../src/OAuth/OAuth';
import * as oauthStorage from '../src/OAuth/oauthStorage';
import {
	CookieStorage,
	CognitoUserSession,
	CognitoIdToken,
	CognitoAccessToken,
	NodeCallback,
	ISignUpResult,
} from 'amazon-cognito-identity-js';
import {
	InternalCognitoUser,
	InternalCognitoUserPool,
} from 'amazon-cognito-identity-js/internals';

const MAX_DEVICES: number = 60;

jest.mock('../src/OAuth/oauthStorage', () => {
	return {
		clearAll: jest.fn(),
		setState: jest.fn(),
		setPKCE: jest.fn(),
		getState: jest.fn(),
		getPKCE: jest.fn(),
	};
});

jest.mock('amazon-cognito-identity-js/lib/CognitoIdToken', () => {
	const CognitoIdToken = () => {};

	CognitoIdToken.prototype.CognitoIdToken = value => {
		CognitoIdToken.prototype.idToken = value;
		return CognitoIdToken;
	};

	CognitoIdToken.prototype.getJwtToken = () => {
		return 'jwtToken';
	};

	return CognitoIdToken;
});

jest.mock('amazon-cognito-identity-js/lib/CognitoUserSession', () => {
	const CognitoUserSession = () => {};

	CognitoUserSession.prototype.CognitoUserSession = options => {
		CognitoUserSession.prototype.options = options;
		return CognitoUserSession;
	};

	CognitoUserSession.prototype.getIdToken = () => {
		return {
			getJwtToken: () => {
				return null;
			},
		};
	};

	CognitoUserSession.prototype.getAccessToken = () => {
		return 'accessToken';
	};

	CognitoUserSession.prototype.isValid = () => {
		return true;
	};

	CognitoUserSession.prototype.getRefreshToken = () => {
		return 'refreshToken';
	};

	return CognitoUserSession;
});

jest.mock('amazon-cognito-identity-js/internals', () => {
	// prettier-ignore
	const InternalCognitoUser = function() {
		// mock private member
		this.signInUserSession = null;
	};

	InternalCognitoUser.prototype.InternalCognitoUser = options => {
		InternalCognitoUser.prototype.options = options;
		return InternalCognitoUser;
	};

	InternalCognitoUser.prototype.getSession = callback => {
		// throw 3;
		callback(null, 'session');
	};

	InternalCognitoUser.prototype.getUserAttributes = callback => {
		callback(null, 'attributes');
	};

	InternalCognitoUser.prototype.getAttributeVerificationCode = (
		attr,
		callback
	) => {
		callback.onSuccess('success');
	};

	InternalCognitoUser.prototype.verifyAttribute = (attr, code, callback) => {
		callback.onSuccess('success');
	};

	InternalCognitoUser.prototype.authenticateUser = (
		authenticationDetails,
		callback
	) => {
		callback.onSuccess('session');
	};

	InternalCognitoUser.prototype.sendMFACode = (code, callback) => {
		callback.onSuccess('session');
	};

	InternalCognitoUser.prototype.resendConfirmationCode = callback => {
		callback(null, {
			CodeDeliveryDetails: {
				AttributeName: 'email',
				DeliveryMedium: 'EMAIL',
				Destination: 'amplify@*****.com',
			},
		});
	};

	InternalCognitoUser.prototype.changePassword = (
		oldPassword,
		newPassword,
		callback
	) => {
		callback(null, 'SUCCESS');
	};

	InternalCognitoUser.prototype.forgotPassword = callback => {
		callback.onSuccess();
	};

	InternalCognitoUser.prototype.confirmPassword = (
		code,
		password,
		callback
	) => {
		callback.onSuccess();
	};

	InternalCognitoUser.prototype.signOut = callback => {
		if (callback && typeof callback === 'function') {
			callback();
		}
	};

	InternalCognitoUser.prototype.globalSignOut = callback => {
		callback.onSuccess();
	};

	InternalCognitoUser.prototype.confirmRegistration = (
		confirmationCode,
		forceAliasCreation,
		callback
	) => {
		callback(null, 'Success');
	};

	InternalCognitoUser.prototype.completeNewPasswordChallenge = (
		password,
		requiredAttributes,
		callback
	) => {
		callback.onSuccess('session');
	};

	InternalCognitoUser.prototype.updateAttributes = (
		attributeList,
		callback
	) => {
		callback(null, 'SUCCESS');
	};
	InternalCognitoUser.prototype.deleteAttributes = (
		attributeList,
		callback
	) => {
		callback(null, 'SUCCESS');
	};
	InternalCognitoUser.prototype.deleteUser = (callback, {}) => {
		callback(null, 'SUCCESS');
	};

	InternalCognitoUser.prototype.setAuthenticationFlowType = type => {};

	InternalCognitoUser.prototype.initiateAuth = (
		authenticationDetails,
		callback
	) => {
		callback.customChallenge('challengeParam');
	};

	InternalCognitoUser.prototype.sendCustomChallengeAnswer = (
		challengeAnswer,
		callback
	) => {
		callback.onSuccess('session');
	};

	InternalCognitoUser.prototype.refreshSession = (refreshToken, callback) => {
		callback(null, 'session');
	};

	InternalCognitoUser.prototype.getUsername = () => {
		return 'username';
	};

	InternalCognitoUser.prototype.getUserData = callback => {
		callback(null, 'data');
	};

	InternalCognitoUser.prototype.setUserMfaPreference = (
		smsMfaSettings,
		softwareTokenMfaSettings,
		callback
	) => {
		callback(null, 'success');
	};

	InternalCognitoUser.prototype.getCachedDeviceKeyAndPassword = () => {
		return 'success';
	};
	InternalCognitoUser.prototype.setDeviceStatusRemembered = callback => {
		callback.onSuccess('success');
	};
	InternalCognitoUser.prototype.forgetDevice = callback => {
		callback.onSuccess('success');
	};
	InternalCognitoUser.prototype.listDevices = (
		limit,
		paginationToken,
		callback
	) => {
		callback.onSuccess('success');
	};
	// prettier-ignore
	InternalCognitoUser.prototype.getSignInUserSession = function() {
		return this.signInUserSession;
	};

	const InternalCognitoUserPool = () => {};

	InternalCognitoUserPool.prototype.InternalCognitoUserPool = options => {
		InternalCognitoUserPool.prototype.options = options;
		return InternalCognitoUserPool;
	};

	InternalCognitoUserPool.prototype.getCurrentUser = () => {
		return {
			username: 'username',
			attributes: { email: 'test@test.com' },
			getSession: callback => {
				// throw 3;
				callback(null, {
					getAccessToken: () => {
						return {
							decodePayload: () => 'payload',
							getJwtToken: () => 'jwt',
						};
					},
				});
			},
		};
	};

	InternalCognitoUserPool.prototype.signUp = (
		username,
		password,
		signUpAttributeList,
		validationData,
		callback,
		clientMetadata,
		customUserAgentDetails?
	) => {
		callback(null, 'signUpResult');
	};

	return {
		...jest.requireActual('amazon-cognito-identity-js/internals'),
		InternalCognitoUser,
		InternalCognitoUserPool,
	};
});

const createMockLocalStorage = () =>
	({
		_items: {},
		getItem(key: string) {
			return this._items[key];
		},
		setItem(key: string, value: string) {
			this._items[key] = value;
		},
		clear() {
			this._items = {};
		},
		removeItem(key: string) {
			delete this._items[key];
		},
	} as unknown as Storage);

import { AuthOptions, SignUpParams, AwsCognitoOAuthOpts } from '../src/types';
import { AuthClass as Auth } from '../src/Auth';
import { InternalAuthClass } from '../src/internals/InternalAuth';
import {
	AuthAction,
	Credentials,
	StorageHelper,
	Hub,
	CustomUserAgentDetails,
} from '@aws-amplify/core';
import { AuthError, NoUserPoolError } from '../src/Errors';
import { AuthErrorTypes } from '../src/types/Auth';
import { mockDeviceArray, transformedMockData } from './mockData';
import { getAuthUserAgentDetails, getAuthUserAgentValue } from '../src/utils';

const authOptions: AuthOptions = {
	userPoolId: 'awsUserPoolsId',
	userPoolWebClientId: 'awsUserPoolsWebClientId',
	region: 'region',
	identityPoolId: 'awsCognitoIdentityPoolId',
	mandatorySignIn: false,
};

const authOptionsWithHostedUIConfig: AuthOptions = {
	userPoolId: 'awsUserPoolsId',
	userPoolWebClientId: 'awsUserPoolsWebClientId',
	region: 'region',
	identityPoolId: 'awsCognitoIdentityPoolId',
	mandatorySignIn: false,
	oauth: {
		domain: 'https://myHostedUIDomain.com',
		scope: [
			'phone',
			'email',
			'openid',
			'profile',
			'aws.cognito.signin.user.admin',
		],
		redirectSignIn: 'http://localhost:3000/',
		redirectSignOut: 'http://localhost:3000/',
		responseType: 'code',
	},
};
const authOptionConfirmationLink: AuthOptions = {
	userPoolId: 'awsUserPoolsId',
	userPoolWebClientId: 'awsUserPoolsWebClientId',
	region: 'region',
	identityPoolId: 'awsCognitoIdentityPoolId',
	mandatorySignIn: false,
	signUpVerificationMethod: 'link',
};

const authOptionsWithClientMetadata: AuthOptions = {
	userPoolId: 'awsUserPoolsId',
	userPoolWebClientId: 'awsUserPoolsWebClientId',
	region: 'region',
	identityPoolId: 'awsCognitoIdentityPoolId',
	mandatorySignIn: false,
	clientMetadata: {
		foo: 'bar',
	},
};

const authOptionsWithNoUserPoolId: AuthOptions = {
	userPoolWebClientId: 'awsUserPoolsWebClientId',
	region: 'region',
	identityPoolId: 'awsCognitoIdentityPoolId',
	mandatorySignIn: false,
};

const userPool = new InternalCognitoUserPool({
	UserPoolId: authOptions.userPoolId,
	ClientId: authOptions.userPoolWebClientId,
});

const signUpResult: ISignUpResult = {
	user: null,
	userConfirmed: true,
	userSub: 'userSub',
	codeDeliveryDetails: null,
};

const idToken = new CognitoIdToken({ IdToken: 'idToken' });
const accessToken = new CognitoAccessToken({ AccessToken: 'accessToken' });

const session = new CognitoUserSession({
	IdToken: idToken,
	AccessToken: accessToken,
});

const authCallbacks = {
	customChallenge: jasmine.any(Function),
	mfaRequired: jasmine.any(Function),
	mfaSetup: jasmine.any(Function),
	newPasswordRequired: jasmine.any(Function),
	onFailure: jasmine.any(Function),
	onSuccess: jasmine.any(Function),
	selectMFAType: jasmine.any(Function),
	totpRequired: jasmine.any(Function),
};

const USER_ADMIN_SCOPE = 'aws.cognito.signin.user.admin';

const userAgentDetails: CustomUserAgentDetails = {
	additionalInfo: [
		['amplify-ui', 'x.x.x'],
		['component', 'ui-comp'],
	],
};

describe('auth user agent test', () => {
	test('signUp', async () => {
		const signUpSpy = jest.spyOn(InternalCognitoUserPool.prototype, 'signUp');

		const attrs = {
			username: 'username',
			password: 'password',
			attributes: {
				email: 'email',
				phone_number: 'phone_number',
				otherAttrs: 'otherAttrs',
			},
		};

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.signUp(attrs, undefined, userAgentDetails);

		expect(signUpSpy).toBeCalledWith(
			attrs.username,
			attrs.password,
			expect.anything(),
			null,
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails)
		);

		signUpSpy.mockClear();
	});

	describe('autoSignInAfterSignUp', () => {
		test('auto confirm', async () => {
			const signUpSpy = jest
				.spyOn(InternalCognitoUserPool.prototype, 'signUp')
				.mockImplementationOnce(
					(
						username,
						password,
						signUpAttributeList,
						validationData,
						callback,
						clientMetadata
					) => {
						callback(null, signUpResult);
					}
				);
			const authenticateUserSpy = jest.spyOn(
				InternalCognitoUser.prototype,
				'authenticateUser'
			);

			const attrs = {
				username: 'username',
				password: 'password',
				attributes: {
					email: 'email',
					phone_number: 'phone_number',
					otherAttrs: 'otherAttrs',
				},
				autoSignIn: { enabled: true },
			};

			const internalAuth = new InternalAuthClass(authOptions);
			await internalAuth.signUp(attrs, undefined, userAgentDetails);

			expect(signUpSpy).toBeCalledWith(
				attrs.username,
				attrs.password,
				expect.anything(),
				null,
				expect.anything(),
				undefined,
				getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails)
			);
			expect(authenticateUserSpy).toBeCalledWith(
				expect.anything(),
				expect.anything(),
				getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails)
			);

			signUpSpy.mockClear();
			authenticateUserSpy.mockClear();
		});

		test('confirmation code', async () => {
			const signUpSpy = jest.spyOn(InternalCognitoUserPool.prototype, 'signUp');
			const confirmRegistrationSpy = jest.spyOn(
				InternalCognitoUser.prototype,
				'confirmRegistration'
			);
			const authenticateUserSpy = jest.spyOn(
				InternalCognitoUser.prototype,
				'authenticateUser'
			);

			const attrs = {
				username: 'username',
				password: 'password',
				attributes: {
					email: 'email',
					phone_number: 'phone_number',
					otherAttrs: 'otherAttrs',
				},
				autoSignIn: { enabled: true },
			};

			const internalAuth = new InternalAuthClass(authOptions);
			await internalAuth.signUp(attrs, undefined, userAgentDetails);
			await internalAuth.confirmSignUp(
				'username',
				'code',
				undefined,
				userAgentDetails
			);

			expect(signUpSpy).toBeCalledWith(
				attrs.username,
				attrs.password,
				expect.anything(),
				null,
				expect.anything(),
				undefined,
				getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails)
			);
			expect(confirmRegistrationSpy).toBeCalledWith(
				'code',
				expect.anything(),
				expect.anything(),
				undefined,
				getAuthUserAgentValue(AuthAction.ConfirmSignUp, userAgentDetails)
			);
			expect(authenticateUserSpy).toBeCalledWith(
				expect.anything(),
				expect.anything(),
				getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails)
			);

			signUpSpy.mockClear();
			confirmRegistrationSpy.mockClear();
			authenticateUserSpy.mockClear();
		});

		test('confirmation link', async () => {
			jest.useFakeTimers();

			const signUpSpy = jest.spyOn(InternalCognitoUserPool.prototype, 'signUp');
			const authenticateUserSpy = jest.spyOn(
				InternalCognitoUser.prototype,
				'authenticateUser'
			);

			const attrs = {
				username: 'username',
				password: 'password',
				attributes: {
					email: 'email',
					phone_number: 'phone_number',
					otherAttrs: 'otherAttrs',
				},
				autoSignIn: { enabled: true },
			};

			const internalAuth = new InternalAuthClass(authOptionConfirmationLink);
			await internalAuth.signUp(attrs, undefined, userAgentDetails);

			jest.advanceTimersByTime(11000);
			expect(signUpSpy).toBeCalledWith(
				attrs.username,
				attrs.password,
				expect.anything(),
				null,
				expect.anything(),
				undefined,
				getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails)
			);
			expect(authenticateUserSpy.mock.calls).toEqual([
				[
					expect.anything(),
					expect.anything(),
					getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails),
				],
				[
					expect.anything(),
					expect.anything(),
					getAuthUserAgentValue(AuthAction.SignUp, userAgentDetails),
				],
			]);

			signUpSpy.mockClear();
			authenticateUserSpy.mockClear();
			jest.useRealTimers();
		});
	});

	test('confirmSignUp', async () => {
		const confirmRegistrationSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'confirmRegistration'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.confirmSignUp(
			'username',
			'code',
			undefined,
			userAgentDetails
		);

		expect(confirmRegistrationSpy).toBeCalledWith(
			'code',
			expect.anything(),
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.ConfirmSignUp, userAgentDetails)
		);

		confirmRegistrationSpy.mockClear();
	});

	test('resendSignUp', async () => {
		const resendConfirmationCodeSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'resendConfirmationCode'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.resendSignUp('username', undefined, userAgentDetails);

		expect(resendConfirmationCodeSpy).toBeCalledWith(
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.ResendSignUp, userAgentDetails)
		);

		resendConfirmationCodeSpy.mockClear();
	});

	test('signIn', async () => {
		const authenticateUserSpy = jest
			.spyOn(InternalCognitoUser.prototype, 'authenticateUser')
			.mockImplementationOnce((authenticationDetails, callback) => {
				callback.onSuccess(session);
			});
		const currentUserPoolUserSpy = jest.spyOn(
			InternalAuthClass.prototype as any,
			'_currentUserPoolUser'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.signIn(
			'username',
			'password',
			undefined,
			userAgentDetails
		);

		expect(authenticateUserSpy).toBeCalledWith(
			expect.anything(),
			expect.anything(),
			getAuthUserAgentValue(AuthAction.SignIn, userAgentDetails)
		);
		expect(currentUserPoolUserSpy).toBeCalledWith(
			undefined,
			getAuthUserAgentDetails(AuthAction.SignIn, userAgentDetails)
		);

		authenticateUserSpy.mockClear();
		currentUserPoolUserSpy.mockClear();
	});

	test('confirmSignIn', async () => {
		const sendMFACodeSpy = jest
			.spyOn(InternalCognitoUser.prototype, 'sendMFACode')
			.mockImplementationOnce((code, callback) => {
				callback.onSuccess(session);
			});

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.confirmSignIn(
			user,
			'code',
			null,
			undefined,
			userAgentDetails
		);

		expect(sendMFACodeSpy).toBeCalledWith(
			'code',
			expect.anything(),
			null,
			undefined,
			getAuthUserAgentValue(AuthAction.ConfirmSignIn, userAgentDetails)
		);

		sendMFACodeSpy.mockClear();
	});

	test('completeNewPassword', async () => {
		const completeNewPasswordChallengeSpy = jest
			.spyOn(InternalCognitoUser.prototype, 'completeNewPasswordChallenge')
			.mockImplementationOnce((password, requiredAttributes, callback) => {
				callback.onSuccess(session);
			});

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.completeNewPassword(
			user,
			'password',
			{},
			undefined,
			userAgentDetails
		);

		expect(completeNewPasswordChallengeSpy).toBeCalledWith(
			'password',
			expect.anything(),
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.CompleteNewPassword, userAgentDetails)
		);

		completeNewPasswordChallengeSpy.mockClear();
	});

	test('userAttributes', async () => {
		const userSessionSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_userSession')
			.mockImplementationOnce(user => {
				return new Promise((res: any, rej) => {
					res('session');
				});
			});
		const getUserAttributesSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'getUserAttributes'
		);

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.userAttributes(user, userAgentDetails);

		expect(userSessionSpy).toBeCalledWith(
			getAuthUserAgentValue(AuthAction.UserAttributes, userAgentDetails),
			user
		);
		expect(getUserAttributesSpy).toBeCalledWith(
			expect.anything(),
			getAuthUserAgentValue(AuthAction.UserAttributes, userAgentDetails)
		);

		userSessionSpy.mockClear();
		getUserAttributesSpy.mockClear();
	});

	test('currentSession', async () => {
		const currentUserPoolUserSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_currentUserPoolUser')
			.mockImplementationOnce(() => {
				return Promise.resolve(user);
			});
		const userSessionSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_userSession')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(session);
				});
			});

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.currentSession(userAgentDetails);

		expect(currentUserPoolUserSpy).toBeCalledWith(
			undefined,
			getAuthUserAgentDetails(AuthAction.CurrentSession, userAgentDetails)
		);
		expect(userSessionSpy).toBeCalledWith(
			getAuthUserAgentValue(AuthAction.CurrentSession, userAgentDetails),
			expect.anything()
		);

		currentUserPoolUserSpy.mockClear();
		userSessionSpy.mockClear();
	});

	test('currentAuthenticatedUser', async () => {
		const currentUserPoolUserSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_currentUserPoolUser')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(user);
				});
			});

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.currentAuthenticatedUser(undefined, userAgentDetails);

		expect(currentUserPoolUserSpy).toBeCalledWith(
			undefined,
			getAuthUserAgentDetails(
				AuthAction.CurrentAuthenticatedUser,
				userAgentDetails
			)
		);

		currentUserPoolUserSpy.mockClear();
	});

	describe('userSession test', () => {
		test('happy case', async () => {
			const getSessionSpy = jest
				.spyOn(InternalCognitoUser.prototype, 'getSession')
				.mockImplementationOnce((callback: any) => {
					callback(null, session);
				});

			const user = new InternalCognitoUser({
				Username: 'username',
				Pool: userPool,
			});

			const internalAuth = new InternalAuthClass(authOptions);
			await internalAuth.userSession(user, userAgentDetails);

			expect(getSessionSpy).toBeCalledWith(
				expect.anything(),
				expect.anything(),
				getAuthUserAgentValue(AuthAction.UserSession, userAgentDetails)
			);

			getSessionSpy.mockClear();
		});

		test('refresh token revoked case', async () => {
			const getSessionSpy = jest
				.spyOn(InternalCognitoUser.prototype, 'getSession')
				.mockImplementationOnce((callback: any) => {
					callback(new Error('Refresh Token has been revoked'), null);
				});
			const signOutSpy = jest
				.spyOn(InternalCognitoUser.prototype, 'signOut')
				.mockImplementationOnce(() => {});

			const user = new InternalCognitoUser({
				Username: 'username',
				Pool: userPool,
			});

			const internalAuth = new InternalAuthClass(authOptions);
			await expect(
				internalAuth.userSession(user, userAgentDetails)
			).rejects.toThrowError('Refresh Token has been revoked');

			expect(getSessionSpy).toBeCalledWith(
				expect.anything(),
				expect.anything(),
				getAuthUserAgentValue(AuthAction.UserSession, userAgentDetails)
			);
			expect(signOutSpy).toBeCalledWith(
				undefined,
				getAuthUserAgentValue(AuthAction.UserSession, userAgentDetails)
			);

			getSessionSpy.mockClear();
			signOutSpy.mockClear();
		});
	});

	test('currentUserCredentials test', async () => {
		const getStorageSpy = jest
			.spyOn(StorageHelper.prototype, 'getStorage')
			.mockImplementation(() => {
				return {
					setItem() {},
					getItem() {
						return null;
					},
					removeItem() {},
				};
			});
		const currentSessionSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_currentSession')
			.mockImplementationOnce(() => {
				return Promise.resolve('session' as any);
			});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.currentUserCredentials(userAgentDetails);

		expect(currentSessionSpy).toBeCalledWith(
			getAuthUserAgentDetails(
				AuthAction.CurrentUserCredentials,
				userAgentDetails
			)
		);

		getStorageSpy.mockClear();
		currentSessionSpy.mockClear();
	});

	test('currentCrendentials', async () => {
		const credentialsGetSpy = jest
			.spyOn(Credentials, 'get')
			.mockImplementationOnce(() => {
				return;
			});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.currentCredentials(userAgentDetails);

		expect(credentialsGetSpy).toBeCalled();
		credentialsGetSpy.mockClear();
	});

	test('verifyUserAttribute test', async () => {
		const getAttributeVerificationCodeSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'getAttributeVerificationCode'
		);

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.verifyUserAttribute(
			user,
			'email',
			undefined,
			userAgentDetails
		);

		expect(getAttributeVerificationCodeSpy).toBeCalledWith(
			'email',
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.VerifyUserAttribute, userAgentDetails)
		);

		getAttributeVerificationCodeSpy.mockClear();
	});

	test('verifyUserAttributeSubmit', async () => {
		const verifyAttributeSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'verifyAttribute'
		);

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.verifyUserAttributeSubmit(
			user,
			'attribute',
			'code',
			userAgentDetails
		);

		expect(verifyAttributeSpy).toBeCalledWith(
			'attribute',
			'code',
			expect.anything(),
			getAuthUserAgentValue(
				AuthAction.VerifyUserAttributeSubmit,
				userAgentDetails
			)
		);

		verifyAttributeSpy.mockClear();
	});

	test('verifyCurrentUserAttribute test', async () => {
		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const currentUserPoolUserSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_currentUserPoolUser')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(user);
				});
			});
		const verifyUserAttributeSpy = jest.spyOn(
			InternalAuthClass.prototype as any,
			'_verifyUserAttribute'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.verifyCurrentUserAttribute('attr', userAgentDetails);

		expect(currentUserPoolUserSpy).toBeCalledWith(
			undefined,
			getAuthUserAgentDetails(
				AuthAction.VerifyCurrentUserAttribute,
				userAgentDetails
			)
		);
		expect(verifyUserAttributeSpy).toBeCalledWith(
			user,
			'attr',
			undefined,
			getAuthUserAgentDetails(
				AuthAction.VerifyCurrentUserAttribute,
				userAgentDetails
			)
		);

		currentUserPoolUserSpy.mockClear();
		verifyUserAttributeSpy.mockClear();
	});

	test('verifyCurrentUserAttributeSubmit test', async () => {
		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const currentUserPoolUserSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_currentUserPoolUser')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(user);
				});
			});
		const verifyUserAttributeSubmitSpy = jest.spyOn(
			InternalAuthClass.prototype as any,
			'_verifyUserAttributeSubmit'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.verifyCurrentUserAttributeSubmit(
			'attr',
			'code',
			userAgentDetails
		);

		expect(currentUserPoolUserSpy).toBeCalledWith(
			undefined,
			getAuthUserAgentDetails(
				AuthAction.VerifyCurrentUserAttributeSubmit,
				userAgentDetails
			)
		);
		expect(verifyUserAttributeSubmitSpy).toBeCalledWith(
			user,
			'attr',
			'code',
			getAuthUserAgentDetails(
				AuthAction.VerifyCurrentUserAttributeSubmit,
				userAgentDetails
			)
		);

		currentUserPoolUserSpy.mockClear();
		verifyUserAttributeSubmitSpy.mockClear();
	});

	describe('signOut test', () => {
		beforeAll(() => {
			jest
				.spyOn(StorageHelper.prototype, 'getStorage')
				.mockImplementation(() => {
					return {
						setItem() {},
						getItem() {},
						removeItem() {},
					};
				});
		});

		test('happy case for source userpool', async () => {
			const user = new InternalCognitoUser({
				Username: 'username',
				Pool: userPool,
			});

			const getCurrentUserSpy = jest
				.spyOn(InternalCognitoUserPool.prototype, 'getCurrentUser')
				.mockImplementationOnce(() => {
					return user;
				});
			const signOutSpy = jest.spyOn(InternalCognitoUser.prototype, 'signOut');

			const internalAuth = new InternalAuthClass(authOptions);
			await internalAuth.signOut(undefined, userAgentDetails);

			expect(signOutSpy).toBeCalledWith(
				expect.anything(),
				getAuthUserAgentValue(AuthAction.SignOut, userAgentDetails)
			);

			getCurrentUserSpy.mockClear();
			signOutSpy.mockClear();
		});

		test('happy case for globalSignOut', async () => {
			const user = new InternalCognitoUser({
				Username: 'username',
				Pool: userPool,
			});

			const getCurrentUserSpy = jest
				.spyOn(InternalCognitoUserPool.prototype, 'getCurrentUser')
				.mockImplementationOnce(() => {
					return user;
				});
			const globalSignOutSpy = jest.spyOn(
				InternalCognitoUser.prototype,
				'globalSignOut'
			);

			const internalAuth = new InternalAuthClass(authOptions);
			await internalAuth.signOut({ global: true }, userAgentDetails);

			expect(globalSignOutSpy).toBeCalledWith(
				expect.anything(),
				getAuthUserAgentValue(AuthAction.SignOut, userAgentDetails)
			);

			getCurrentUserSpy.mockClear();
			globalSignOutSpy.mockClear();
		});
	});

	test('changePassword', async () => {
		const userSessionSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_userSession')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(session);
				});
			});
		const changePasswordSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'changePassword'
		);

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});
		const oldPassword = 'oldPassword1';
		const newPassword = 'newPassword1.';

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.changePassword(
			user,
			oldPassword,
			newPassword,
			undefined,
			userAgentDetails
		);

		expect(userSessionSpy).toBeCalledWith(
			getAuthUserAgentValue(AuthAction.ChangePassword, userAgentDetails),
			user
		);
		expect(changePasswordSpy).toBeCalledWith(
			'oldPassword1',
			'newPassword1.',
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.ChangePassword, userAgentDetails)
		);

		userSessionSpy.mockClear();
		changePasswordSpy.mockClear();
	});

	test('forgotPassword', async () => {
		const forgotPasswordSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'forgotPassword'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.forgotPassword('username', undefined, userAgentDetails);

		expect(forgotPasswordSpy).toBeCalledWith(
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.ForgotPassword, userAgentDetails)
		);

		forgotPasswordSpy.mockClear();
	});

	test('forgotPasswordSubmit', async () => {
		const confirmPasswordSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'confirmPassword'
		);

		const internalAuth = new InternalAuthClass(authOptions);

		await internalAuth.forgotPasswordSubmit(
			'username',
			'code',
			'password',
			undefined,
			userAgentDetails
		);

		expect(confirmPasswordSpy).toBeCalledWith(
			'code',
			'password',
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.ForgotPasswordSubmit, userAgentDetails)
		);

		confirmPasswordSpy.mockClear();
	});

	test('currentUserInfo test', async () => {
		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});

		const currentUserPoolUserSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_currentUserPoolUser')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(user);
				});
			});
		const userAttributesSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_userAttributes')
			.mockImplementationOnce(() => {
				return new Promise((res: any, rej) => {
					res([{ Name: 'email', Value: 'email' }]);
				});
			});
		const currentCredentialsSpy = jest.spyOn(
			InternalAuthClass.prototype,
			'currentCredentials'
		);

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.currentUserInfo(userAgentDetails);

		expect(currentUserPoolUserSpy).toBeCalledWith(
			undefined,
			getAuthUserAgentDetails(AuthAction.CurrentUserInfo, userAgentDetails)
		);
		expect(userAttributesSpy).toBeCalledWith(
			expect.anything(),
			getAuthUserAgentDetails(AuthAction.CurrentUserInfo, userAgentDetails)
		);
		expect(currentCredentialsSpy).toBeCalled();

		currentUserPoolUserSpy.mockClear();
		userAttributesSpy.mockClear();
		currentCredentialsSpy.mockClear();
	});

	test('updateUserAttributes test', async () => {
		const userSessionSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_userSession')
			.mockImplementationOnce(() => {
				return new Promise((res, rej) => {
					res(session);
				});
			});
		const updateAttributesSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'updateAttributes'
		);

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});
		const attributes = {
			email: 'email',
			phone_number: 'phone_number',
			sub: 'sub',
		};

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.updateUserAttributes(
			user,
			attributes,
			undefined,
			userAgentDetails
		);

		expect(userSessionSpy).toBeCalledWith(
			getAuthUserAgentValue(AuthAction.UpdateUserAttributes, userAgentDetails),
			expect.anything()
		);
		expect(updateAttributesSpy).toBeCalledWith(
			expect.anything(),
			expect.anything(),
			undefined,
			getAuthUserAgentValue(AuthAction.UpdateUserAttributes, userAgentDetails)
		);

		userSessionSpy.mockClear();
		updateAttributesSpy.mockClear();
	});

	test('deleteUserAttributes test', async () => {
		const userSessionSpy = jest
			.spyOn(InternalAuthClass.prototype as any, '_userSession')
			.mockImplementationOnce(() => {
				return new Promise(res => {
					res(session);
				});
			});
		const deleteAttributesSpy = jest.spyOn(
			InternalCognitoUser.prototype,
			'deleteAttributes'
		);

		const user = new InternalCognitoUser({
			Username: 'username',
			Pool: userPool,
		});
		const attributeNames = ['email', 'phone_number'];

		const internalAuth = new InternalAuthClass(authOptions);
		await internalAuth.deleteUserAttributes(
			user,
			attributeNames,
			userAgentDetails
		);

		const userAgentValue = getAuthUserAgentValue(
			AuthAction.DeleteUserAttributes,
			userAgentDetails
		);

		expect(userSessionSpy).toBeCalledWith(userAgentValue, expect.anything());
		expect(deleteAttributesSpy).toBeCalledWith(
			expect.anything(),
			expect.anything(),
			userAgentValue
		);

		userSessionSpy.mockClear();
		deleteAttributesSpy.mockClear();
	});

});
