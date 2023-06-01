import { Platform, getUserAgent, rerunFrameworkDetection } from './Platform';
import { category } from './Platform/constants';
// constructor
function UserAgent() {}
// public
UserAgent.prototype.userAgent = getUserAgent();

export const appendToCognitoUserAgent = content => {
	if (!content) {
		return;
	}
	if (
		UserAgent.prototype.userAgent &&
		!UserAgent.prototype.userAgent.includes(content)
	) {
		UserAgent.prototype.userAgent = UserAgent.prototype.userAgent.concat(
			' ',
			content
		);
	}
	if (!UserAgent.prototype.userAgent || UserAgent.prototype.userAgent === '') {
		UserAgent.prototype.userAgent = content;
	}
};

// class for defining the amzn user-agent
export default UserAgent;

export const getAmplifyUserAgentString = ({ action, framework } = {}) => {
	rerunFrameworkDetection();
	const uaAction = action ?? AuthAction.None;
	const uaFramework = framework ?? Platform.framework;

	const userAgent = `${UserAgent.prototype.userAgent} ${category}/${uaAction} framework/${uaFramework}`;

	return userAgent;
};
