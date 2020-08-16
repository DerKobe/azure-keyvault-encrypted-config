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
export function makeQuerablePromise(promise: Promise<any>): QuerablePromise<any> {
  // Don't modify any promise that has been already modified.
  if (promise.hasOwnProperty('isResolved')) {
    return promise as QuerablePromise<any>;
  }

  // Set initial state
  let isPending = true;
  let isRejected = false;
  let isFulfilled = false;
  let isResolved = false;

  // Observe the promise, saving the fulfillment in a closure scope.
  // @ts-ignore
  const result: QuerablePromise<any> = promise.then(
    v => {
      isResolved = true;
      isFulfilled = true;
      isPending = false;
      return v;
    },
    e => {
      isResolved = true;
      isRejected = true;
      isPending = false;
      throw e;
    },
  );

  result.isResolved = () => isResolved;
  result.isFulfilled = () => isFulfilled;
  result.isPending = () => isPending;
  result.isRejected = () => isRejected;

  return result;
}
