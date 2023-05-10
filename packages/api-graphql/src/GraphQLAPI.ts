import { Amplify } from '@aws-amplify/core';
import { GraphQLAPIInterface, GraphQLOptions, GraphQLResult } from './types';
import { InternalGraphQLAPIClass } from './internal';
import Observable from 'zen-observable-ts';

export const graphqlOperation = (
	query,
	variables = {},
	authToken?: string
) => ({
	query,
	variables,
	authToken,
});

/**
 * Export Cloud Logic APIs
 */
export class GraphQLAPIClass
	extends InternalGraphQLAPIClass
	implements GraphQLAPIInterface
{
	/**
	 * Executes a GraphQL operation
	 *
	 * @param options - GraphQL Options
	 * @param [additionalHeaders] - headers to merge in after any `graphql_headers` set in the config
	 * @returns An Observable if the query is a subscription query, else a promise of the graphql result.
	 */
	graphql<T = any>(
		options: GraphQLOptions,
		additionalHeaders?: { [key: string]: string }
	): Observable<GraphQLResult<T>> | Promise<GraphQLResult<T>> {
		return super.graphql(options, additionalHeaders);
	}
}

export const GraphQLAPI = new GraphQLAPIClass(null);
Amplify.register(GraphQLAPI);
