export enum Framework {
	None = '0',
	ReactNative = '1',
}

export enum Category {
	API = 'api',
	Auth = 'auth',
	DataStore = 'datastore',
	Geo = 'geo',
	InAppMessaging = 'inappmessaging',
	Interactions = 'interactions',
	Predictions = 'predictions',
	PubSub = 'pubsub',
	PushNotification = 'pushnotification',
	Storage = 'storage',
}

// Actions
/* TODO: Replace 'None' with all expected Actions */
export enum ApiAction {
	GraphQl = '1',
	Get = '2',
	Post = '3',
	Put = '4',
	Patch = '5',
	Del = '6',
	Head = '7',
}
export enum AuthAction {
	None = '0',
}
export enum DataStoreAction {
	GraphQL = '1',
	Subscribe = '2',
}
export enum GeoAction {
	None = '0',
}
export enum InAppMessagingAction {
	None = '0',
}
export enum InteractionsAction {
	None = '0',
}
export enum PredictionsAction {
	None = '0',
}
export enum PubSubAction {
	Subscribe = '1',
}
export enum PushNotificationAction {
	None = '0',
}
export enum StorageAction {
	None = '0',
}

type ActionMap = {
	[Category.Auth]: AuthAction;
	[Category.API]: ApiAction;
	[Category.DataStore]: DataStoreAction;
	[Category.Geo]: GeoAction;
	[Category.InAppMessaging]: InAppMessagingAction;
	[Category.Interactions]: InteractionsAction;
	[Category.Predictions]: PredictionsAction;
	[Category.PubSub]: PubSubAction;
	[Category.PushNotification]: PushNotificationAction;
	[Category.Storage]: StorageAction;
};

type UserAgentDetailsWithCategory<T extends Category> =
	CustomUserAgentDetailsBase & {
		category: T;
		action: T extends keyof ActionMap ? ActionMap[T] : never;
	};

type CustomUserAgentDetailsBase = {
	framework?: Framework;
};

export type CustomUserAgentDetails =
	| (CustomUserAgentDetailsBase & { category?: never; action?: never })
	| UserAgentDetailsWithCategory<Category.API>
	| UserAgentDetailsWithCategory<Category.Auth>
	| UserAgentDetailsWithCategory<Category.DataStore>
	| UserAgentDetailsWithCategory<Category.Geo>
	| UserAgentDetailsWithCategory<Category.Interactions>
	| UserAgentDetailsWithCategory<Category.InAppMessaging>
	| UserAgentDetailsWithCategory<Category.Predictions>
	| UserAgentDetailsWithCategory<Category.PubSub>
	| UserAgentDetailsWithCategory<Category.PushNotification>
	| UserAgentDetailsWithCategory<Category.Storage>;
