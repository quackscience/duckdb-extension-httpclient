<img src="https://github.com/user-attachments/assets/46a5c546-7e9b-42c7-87f4-bc8defe674e0" width=250 />

# DuckDB HTTP Client Extension
This very experimental extension spawns an HTTP Client from within DuckDB resolving GET/POST requests.<br>

> Experimental: USE AT YOUR OWN RISK!

### 📦 Installation
```sql
INSTALL http_client FROM community;
LOAD http_client;
```

### Functions
- `http_get(url)`
- `http_post(url, headers, params)`

### Examples
#### GET
```sql
D WITH __input AS (
    SELECT
      http_get(
          'https://httpbin.org/delay/0'
      ) AS res
  ),
  __response AS (
    SELECT
      (res->>'status')::INT AS status,
      (res->>'reason') AS reason,
      unnest( from_json(((res->>'body')::JSON)->'headers', '{"Host": "VARCHAR"}') ) AS features
    FROM
      __input
  )
  SELECT
    __response.status,
    __response.reason,
    __response.Host AS host,
  FROM
    __response
  ;
┌────────┬─────────┬─────────────┐
│ status │ reason  │    host     │
│ int32  │ varchar │   varchar   │
├────────┼─────────┼─────────────┤
│    200 │ OK      │ httpbin.org │
└────────┴─────────┴─────────────┘
```

#### POST
```sql
D WITH __input AS (
    SELECT
      http_post(
          'https://httpbin.org/delay/0',
          headers => MAP {
            'accept': 'application/json',
          },
          params => MAP {
          }
      ) AS res
  ),
  __response AS (
    SELECT
      (res->>'status')::INT AS status,
      (res->>'reason') AS reason,
      unnest( from_json(((res->>'body')::JSON)->'headers', '{"Host": "VARCHAR"}') ) AS features
    FROM
      __input
  )
  SELECT
    __response.status,
    __response.reason,
    __response.Host AS host,
  FROM
    __response
  ;
┌────────┬─────────┬─────────────┐
│ status │ reason  │    host     │
│ int32  │ varchar │   varchar   │
├────────┼─────────┼─────────────┤
│    200 │ OK      │ httpbin.org │
└────────┴─────────┴─────────────┘
```

#### Full Example w/ spatial data
This is the original example by @ahuarte47 inspiring this community extension.

```sql
D SET autoinstall_known_extensions=1; SET autoload_known_extensions=1;
D LOAD json; LOAD httpfs; LOAD spatial;

D WITH __input AS (
    SELECT
      http_get(
        'https://earth-search.aws.element84.com/v0/search')
      AS res
  ),
  __features AS (
    SELECT
      unnest( from_json(((res->>'body')::JSON)->'features', '["json"]') )
      AS features
    FROM
      __input
  )
  SELECT
    features->>'id' AS id,
    features->'properties'->>'sentinel:product_id' AS product_id,
    concat(
      'T',
      features->'properties'->>'sentinel:utm_zone',
      features->'properties'->>'sentinel:latitude_band',
      features->'properties'->>'sentinel:grid_square'
    ) AS grid_id,
    ST_GeomFromGeoJSON(features->'geometry') AS geom
  FROM
    __features
  ;
┌──────────────────────┬──────────────────────┬─────────┬──────────────────────────────────────────────────────────────────────────────────┐
│          id          │      product_id      │ grid_id │                                       geom                                       │
│       varchar        │       varchar        │ varchar │                                     geometry                                     │
├──────────────────────┼──────────────────────┼─────────┼──────────────────────────────────────────────────────────────────────────────────┤
│ S2B_55GDP_20241003…  │ S2B_MSIL2A_2024100…  │ T55GDP  │ POLYGON ((146.7963024570636 -42.53859799130381, 145.7818492341335 -42.53284395…  │
│ S2B_55HEC_20241003…  │ S2B_MSIL2A_2024100…  │ T55HEC  │ POLYGON ((146.9997932100229 -34.429312828654396, 146.9997955899612 -33.4390429…  │
│ S2B_55JHN_20241003…  │ S2B_MSIL2A_2024100…  │ T55JHN  │ POLYGON ((149.9810192714723 -25.374826158099584, 149.9573295859729 -24.3845516…  │
│ S2B_15MWT_20230506…  │ S2B_MSIL2A_2023050…  │ T15MWT  │ POLYGON ((-92.01266261624052 -2.357695714729873, -92.0560908879947 -2.35076658…  │
│ S2B_16PBT_20230506…  │ S2B_MSIL2A_2023050…  │ T16PBT  │ POLYGON ((-88.74518736203468 11.690012668805194, -88.9516536515512 11.72635252…  │
│ S2B_16PCT_20230506…  │ S2B_MSIL2A_2023050…  │ T16PCT  │ POLYGON ((-87.82703591176752 11.483638069337541, -88.8349824533826 11.70734355…  │
│ S2B_15PZP_20230506…  │ S2B_MSIL2A_2023050…  │ T15PZP  │ POLYGON ((-89.24113885498912 11.784951995968179, -89.38831685490888 11.8080246…  │
│ S2B_16PET_20230506…  │ S2B_MSIL2A_2023050…  │ T16PET  │ POLYGON ((-87.00017408768262 11.277451946475995, -87.00017438483464 11.7600349…  │
│ S2B_16PBU_20230506…  │ S2B_MSIL2A_2023050…  │ T16PBU  │ POLYGON ((-88.74518962519173 11.690373971442378, -89.62017907866615 11.8466519…  │
│ S2B_16PDU_20230506…  │ S2B_MSIL2A_2023050…  │ T16PDU  │ POLYGON ((-87.91783982214183 11.670141095427311, -87.92096676562824 12.5828090…  │
├──────────────────────┴──────────────────────┴─────────┴──────────────────────────────────────────────────────────────────────────────────┤
│ 10 rows                                                                                                                        4 columns │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
