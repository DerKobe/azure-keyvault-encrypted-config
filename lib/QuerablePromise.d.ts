export interface QuerablePromise<T> extends Promise<T> {
    isPending: () => boolean;
    isRejected: () => boolean;
    isFulfilled: () => boolean;
    isResolved: () => boolean;
}
/**
 * This function allow you to modify a JS Promise by adding some status properties.
 * Based on: http://stackoverflow.com/questions/21485545/is-there-a-way-to-tell-if-an-es6-promise-is-fulfilled-rejected-resolved
 * But modified according to the specs of promises : https://promisesaplus.com/
 */
export declare function makeQuerablePromise(promise: Promise<any>): QuerablePromise<any>;
