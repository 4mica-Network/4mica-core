# DefaultApi

All URIs are relative to *https://develop.4mica.xyz*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**getPublicParams**](#getpublicparams) | **POST** /core/getPublicParams | Get core public parameters|
|[**getTransactionsByHash**](#gettransactionsbyhash) | **POST** /core/getTransactionsByHash | Get transactions by their hashes|
|[**getUser**](#getuser) | **POST** /core/getUser | Get user information|
|[**issuePaymentCert**](#issuepaymentcert) | **POST** /core/issuePaymentCert | Issue payment certificate|
|[**registerUser**](#registeruser) | **POST** /core/registerUser | Register a user|
|[**verifyTransaction**](#verifytransaction) | **POST** /core/verifyTransaction | Verify a transaction|

# **getPublicParams**
> CorePublicParameters getPublicParams()


### Example

```typescript
import {
    DefaultApi,
    Configuration
} from './api';

const configuration = new Configuration();
const apiInstance = new DefaultApi(configuration);

let body: object; // (optional)

const { status, data } = await apiInstance.getPublicParams(
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |


### Return type

**CorePublicParameters**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Core public parameters |  -  |
|**400** | Bad request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **getTransactionsByHash**
> Array<UserTransactionInfo> getTransactionsByHash(getTransactionsByHashRequest)


### Example

```typescript
import {
    DefaultApi,
    Configuration,
    GetTransactionsByHashRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new DefaultApi(configuration);

let getTransactionsByHashRequest: GetTransactionsByHashRequest; //

const { status, data } = await apiInstance.getTransactionsByHash(
    getTransactionsByHashRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **getTransactionsByHashRequest** | **GetTransactionsByHashRequest**|  | |


### Return type

**Array<UserTransactionInfo>**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | List of user transactions |  -  |
|**400** | Invalid or missing hashes |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **getUser**
> UserInfo getUser(registerUserRequest)


### Example

```typescript
import {
    DefaultApi,
    Configuration,
    RegisterUserRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new DefaultApi(configuration);

let registerUserRequest: RegisterUserRequest; //

const { status, data } = await apiInstance.getUser(
    registerUserRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **registerUserRequest** | **RegisterUserRequest**|  | |


### Return type

**UserInfo**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | UserInfo or null if not found |  -  |
|**400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **issuePaymentCert**
> string issuePaymentCert(issuePaymentCertRequest)


### Example

```typescript
import {
    DefaultApi,
    Configuration,
    IssuePaymentCertRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new DefaultApi(configuration);

let issuePaymentCertRequest: IssuePaymentCertRequest; //

const { status, data } = await apiInstance.issuePaymentCert(
    issuePaymentCertRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **issuePaymentCertRequest** | **IssuePaymentCertRequest**|  | |


### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | BLS certificate |  -  |
|**400** | Invalid transaction details |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **registerUser**
> string registerUser(registerUserRequest)


### Example

```typescript
import {
    DefaultApi,
    Configuration,
    RegisterUserRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new DefaultApi(configuration);

let registerUserRequest: RegisterUserRequest; //

const { status, data } = await apiInstance.registerUser(
    registerUserRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **registerUserRequest** | **RegisterUserRequest**|  | |


### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Registration success |  -  |
|**400** | Invalid user address |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **verifyTransaction**
> TransactionVerificationResult verifyTransaction(verifyTransactionRequest)


### Example

```typescript
import {
    DefaultApi,
    Configuration,
    VerifyTransactionRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new DefaultApi(configuration);

let verifyTransactionRequest: VerifyTransactionRequest; //

const { status, data } = await apiInstance.verifyTransaction(
    verifyTransactionRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **verifyTransactionRequest** | **VerifyTransactionRequest**|  | |


### Return type

**TransactionVerificationResult**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Transaction verification result |  -  |
|**400** | Invalid transaction hash |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

