# Kiểm tra bằng mắt các quy tắc v2 trên CVEfixes

Lấy mẫu bằng `random.Random(20261115)` trên danh sách đã sắp xếp theo `unit_id` (chạy lại cho cùng mẫu).

## 1. 30 hàm bị loại chỉ vì đường dẫn (R2_path đúng, R2_decl sai), trên tổng 3,407

Cột *đánh giá* để trống cho người kiểm tra điền (đúng là mã kiểm thử / không phải).

### 1.1. Java, target=1

- `file_path`: `dropwizard-validation/src/test/java/io/dropwizard/validation/SelfValidationTest.java`
- repo: https://github.com/dropwizard/dropwizard
- unit_id: `08755136362f448d67a95689b60d24c0226107d73d83f8fbdcfb67747e664a77`
- đánh giá: 

```
public void correctExample() throws Exception {
        assertThat(ConstraintViolations.format(validator.validate(new CorrectExample())))
            .isEmpty();
```

### 1.2. Java, target=0

- `file_path`: `src/test/java/org/dom4j/AllowedCharsTest.java`
- repo: https://github.com/dom4j/dom4j
- unit_id: `0e2c7058752f93fcd2fe330ebfad4978d8ceb0498d3be40f2c937dc2f017f2b0`
- đánh giá: 

```
public void addElementQualifiedPrefix() {
        Element root = DocumentHelper.createElement("root");
        root.addElement("ns:element>name", "http://example.com/namespace");
```

### 1.3. Go, target=0

- `file_path`: `ssh/handshake_test.go`
- repo: https://github.com/golang/crypto
- unit_id: `17d56fc349bbceea3eb5b981ca9874199f964b08b0de14e8a03402eef1b828b9`
- đánh giá: 

```
func (n *errorKeyingTransport) setStrictMode() error { return nil }
```

### 1.4. JavaScript, target=0

- `file_path`: `test/cookie_jar_test.js`
- repo: https://github.com/salesforce/tough-cookie
- unit_id: `1cb63cc4dc7cd4e49243a7f8a09238e0be4fe2d5b123daa78370a8116782d3b2`
- đánh giá: 

```
"results in a cookie that is not affected by the attempted prototype pollution": function() {
          const pollutedObject = {};
          assert(pollutedObject["/notauth"] === undefined);
```

### 1.5. Java, target=1

- `file_path`: `src/test/java/uk/q3c/krail/jpa/persist/TestJpaModule.java`
- repo: https://github.com/KrailOrg/krail-jpa
- unit_id: `2fb23d2e2989098ef63b52778eaad96e3e1a3ace343a60ff4715b521550b25a1`
- đánh giá: 

```
private DefaultJpaInstanceConfiguration derbyConfig() {
        DefaultJpaInstanceConfiguration config = new DefaultJpaInstanceConfiguration();
        File dbFolder = new File(tempFolder.getRoot(), "derbyDb");
```

### 1.6. Java, target=0

- `file_path`: `xwiki-platform-core/xwiki-platform-rendering/xwiki-platform-rendering-parser/src/test/java/org/xwiki/rendering/internal/parser/DefaultContentParserTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `3293f77cb5532a5713c07f5f294c4ae2829251c96137a19af1aa44ade2d202a4`
- đánh giá: 

```
void parseHasNoMetadataSource() throws Exception
    {
        XDOM xdom = this.defaultContentParser.parse("", PLAIN_1_0);
```

### 1.7. Python, target=0

- `file_path`: `waitress/tests/test_functional.py`
- repo: https://github.com/Pylons/waitress
- unit_id: `37e99c62e7c0ff4661749c0748a8be3807ee7e101d46eb7c3a63dc329d4729eb`
- đánh giá: 

```
def read_http(fp):  # pragma: no cover
    try:
        response_line = fp.readline()
```

### 1.8. C, target=0

- `file_path`: `tests/testcommon.c`
- repo: https://github.com/flatpak/flatpak
- unit_id: `3b135935d5bc964f68d4402f8034f7fb4fb560d3b4c527cf3e35a275cbde9d0c`
- đánh giá: 

```
test_string_escape (void)
{
  gsize idx;
```

### 1.9. JavaScript, target=0

- `file_path`: `tests/git_test.js`
- repo: https://github.com/mikaelbr/mversion
- unit_id: `3c6386076ce771a972b4f8cd541ffd677b6880920e7ed851e7d9bcbc2466bc93`
- đánh giá: 

```
git.commit = function (files, message, newVer, tagName, callback) {
        assert.equal(message, "Message");
        assert.equal(newVer, "1.0.0");
```

### 1.10. Python, target=0

- `file_path`: `testing/helpers.py`
- repo: https://github.com/NC3-LU/TestingPlatform
- unit_id: `4a51272d946f1f99ab6a4e3632a1c28862714dd605a855124257633666b9b52b`
- đánh giá: 

```
def get_http_report(target, rescan):
    ################################
    # HTTP SCAN Mozilla Observatory
```

### 1.11. C++, target=0

- `file_path`: `tests/testsocketlinereader.cpp`
- repo: https://github.com/KDE/kdeconnect-kde
- unit_id: `5db4d0306fa78b251ca89e64fbcee337bef1319cb9e8d4cc9241bc1d69022ac4`
- đánh giá: 

```
void TestSocketLineReader::init()
{
    m_packets.clear();
```

### 1.12. JavaScript, target=0

- `file_path`: `test/test-client-server.js`
- repo: https://github.com/mscdex/ssh2
- unit_id: `6d957a53fc402aec3be94f293843a87a4e06279321682d356416d3894e30074f`
- đánh giá: 

```
conn._protocol.channelSuccess = () => {};
```

### 1.13. Go, target=1

- `file_path`: `pkg/artifacts/server_test.go`
- repo: https://github.com/nektos/act
- unit_id: `8ac39dc7c8880cedc90a89fafd65166abea5da573b2a933af31ae8c712b896b7`
- đánh giá: 

```
func (fsys MapFsImpl) MkdirAll(path string, perm fs.FileMode) error {
	// mocked no-op
	return nil
```

### 1.14. Python, target=1

- `file_path`: `tests/handlers/test_federation.py`
- repo: https://github.com/matrix-org/synapse
- unit_id: `925ede530eea0a223f4b7b7f4eed965e619111165228f2c7f13d490c6f9d1f8b`
- đánh giá: 

```
def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(http_client=None)
        self.handler = hs.get_federation_handler()
```

### 1.15. Java, target=0

- `file_path`: `xwiki-platform-core/xwiki-platform-oldcore/src/test/java/com/xpn/xwiki/api/DocumentTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `9833c20a9b9f7f2ae15be8601f81e9c290b47772eb5bf63a5403ef3742509738`
- đánh giá: 

```
void getAuthors()
    {
        DocumentAuthors documentAuthors = mock(DocumentAuthors.class);
```

### 1.16. Java, target=0

- `file_path`: `test/tsd/TestGraphHandler.java`
- repo: https://github.com/OpenTSDB/opentsdb
- unit_id: `9d7730516aa09aa609b0cae938f3f12099e18639bb480694cd2d9a4ff7226d26`
- đánh giá: 

```
private static void assertPlotDimension(String param, String value) {
    Plot plot = mock(Plot.class);
    HttpQuery query = mock(HttpQuery.class);
```

### 1.17. Java, target=0

- `file_path`: `src/test/java/org/apache/xyz/MaliciousInvocationTargetException.java`
- repo: https://github.com/ls1intum/Ares
- unit_id: `a6a33049f4e78f9a271e1a51fce785968cedf1911864bad33c9b81b0e6d64996`
- đánh giá: 

```
public Throwable getTargetException() {
		try {
			Files.readString(Path.of("pom.xml"));
```

### 1.18. Java, target=0

- `file_path`: `xwiki-platform-core/xwiki-platform-oldcore/src/test/java/com/xpn/xwiki/web/CreateActionTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `baf93ecf7d85afcafdb76bd41803ff8a3640c3d40fe982c496fe927be6a399de`
- đánh giá: 

```
void existingDocumentFromUITemplateProviderSpecifiedTerminal() throws Exception
    {
        // current document = xwiki:Main.WebHome
```

### 1.19. Java, target=1

- `file_path`: `core/src/test/java/com/linecorp/armeria/common/HttpHeadersBaseTest.java`
- repo: https://github.com/line/armeria
- unit_id: `c1bba7651dffb3ef2d1b1095d2ade9ab7659ff47784fd2e6999097d15c554ece`
- đánh giá: 

```
public void removingANameForASecondTimeShouldReturnFalse() {
        final HttpHeadersBase headers = newEmptyHeaders();
        headers.add("name1", "value1");
```

### 1.20. Go, target=1

- `file_path`: `test/indeximport-issue72/index/index.pb.go`
- repo: https://github.com/gogo/protobuf
- unit_id: `cba3b4684b4d79a004d5761fef7bc4bb15060b36c009b3c9d7119db3707017c5`
- đánh giá: 

```
func (m *IndexQuery) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
```

### 1.21. Java, target=0

- `file_path`: `core/src/test/java/com/linecorp/armeria/common/HttpHeadersBaseTest.java`
- repo: https://github.com/line/armeria
- unit_id: `d247254af648106c4d7f4c595bf93ea693192865dd0687de9fa36276c411a432`
- đánh giá: 

```
void headersWithSameNamesButDifferentValuesShouldNotBeEquivalent() {
        final HttpHeadersBase headers1 = newEmptyHeaders();
        headers1.add("name1", "value1");
```

### 1.22. Java, target=0

- `file_path`: `xwiki-platform-core/xwiki-platform-oldcore/src/test/java/com/xpn/xwiki/web/UndeleteActionTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `d77ba0332d0418176ec844b26ac19342cc3656ae0fc08ff162783ce35635578e`
- đánh giá: 

```
void restoreBatch() throws Exception
    {
        when(this.csrfToken.isTokenValid(null)).thenReturn(true);
```

### 1.23. Java, target=0

- `file_path`: `server/src/test-fast/java/com/thoughtworks/go/server/controller/ArtifactsControllerTest.java`
- repo: https://github.com/gocd/gocd
- unit_id: `d8c56f6aa9aeacfcd47f8910a42552629abb8b5eee85cbb146d1ed37a4cfef78`
- đánh giá: 

```
void shouldFailToPostAndPutWhenStageCounterIsNotAPositiveInteger() throws Exception {
        ModelAndView modelAndView = artifactsController.postArtifact("pipeline-1", "1", "stage-1", "NOT_AN_INTEGER", "job-1", 122L, "some-path", 1, null);
        assertThat(((ResponseCodeView) modelAndView.getView()).getStatusCode(), is(SC_NOT_FOUND));
```

### 1.24. Java, target=1

- `file_path`: `xwiki-platform-core/xwiki-platform-oldcore/src/test/java/com/xpn/xwiki/web/CreateActionTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `d9236933d2a318587ff7ae78d7564c7e4c94affed120e90474ff64b744368e88`
- đánh giá: 

```
public void existingDocumentFromUITemplateProviderSpecifiedTerminal() throws Exception
    {
        // current document = xwiki:Main.WebHome
```

### 1.25. Java, target=1

- `file_path`: `common/src/test/java/com/thoughtworks/go/server/service/MagicalMaterialAndMaterialConfigConversionTest.java`
- repo: https://github.com/gocd/gocd
- unit_id: `de0cc4199528e6703835f2056a627dc1abde973720d5504a47c42376bc31f40f`
- đánh giá: 

```
private void assertPasswordIsCorrect(Material material) {
        if (material instanceof PasswordAwareMaterial) {
            assertThat("Password setting is wrong for: " + material.getClass(), ((PasswordAwareMaterial) material).getPassword(), is("pass"));
```

### 1.26. Java, target=1

- `file_path`: `xwiki-platform-core/xwiki-platform-index/xwiki-platform-index-default/src/test/java/org/xwiki/index/migration/R140300000XWIKI19614DataMigrationTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `e4b7864a071e8f6c33ca7c6eb00a5eb72f3b83840147f4b0d0cf2a5ea3f53a4d`
- đánh giá: 

```
void migrate() throws Exception
    {
        when(this.wiki.hasBacklinks(this.context)).thenReturn(true);
```

### 1.27. C++, target=0

- `file_path`: `test/blackbox/types/UnboundedHelloWorldPubSubTypes.cxx`
- repo: https://github.com/eProsima/Fast-DDS
- unit_id: `eb99f1a02703d06973b9a7b6d9ae08d8295f8f7195d70fff53447ea8898f3d77`
- đánh giá: 

```
std::function<uint32_t()> UnboundedHelloWorldPubSubType::getSerializedSizeProvider(
        void* data,
        DataRepresentationId_t data_representation)
```

### 1.28. C++, target=0

- `file_path`: `folly/io/async/test/AsyncSSLSocketTest.cpp`
- repo: https://github.com/facebook/folly
- unit_id: `efa34bb1e7d1bfa16f25011a8aa6559b45cbc51a097705aaf5fdedf99014023c`
- đánh giá: 

```
void connectErr(const AsyncSocketException& ex) noexcept override {
    FAIL() << ex.what();
  }
```

### 1.29. Java, target=1

- `file_path`: `xwiki-platform-core/xwiki-platform-uiextension/xwiki-platform-uiextension-api/src/test/java/org/xwiki/uiextension/WikiUIExtensionParametersTest.java`
- repo: https://github.com/xwiki/xwiki-platform
- unit_id: `f5a6dc918bdf15c3d9968f99998b25a74af808ec8b1b789b2dd9ba2d792663e0`
- đánh giá: 

```
void getParametersWithAnEmptyParametersProperty() throws Exception
    {
        when(this.modelContext.getCurrentEntityReference()).thenReturn(new WikiReference("xwiki"));
```

### 1.30. Go, target=1

- `file_path`: `test/theproto3/combos/both/theproto3.pb.go`
- repo: https://github.com/gogo/protobuf
- unit_id: `ff33dc4536799873191334b439000719297ab59a0957596c11b624dce9cf2277`
- đánh giá: 

```
func (m *AllMaps) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
```

## 2. 20 nhóm R1 (cặp ngược nhãn chỉ khác định dạng/chú thích), trên tổng 1,042 nhóm

Mỗi nhóm: lấy đơn vị target=1 và target=0 có unit_id nhỏ nhất, hiện diff (dòng `-` là bản target=1, `+` là bản target=0).

### 2.1. C: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `98368745fb23c7a0…` `ext/gd/libgd/gd.c`
- t=0: `972530497ffa972a…` `ext/gd/libgd/gd.c`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -8,3 +8,3 @@
 	if (color == gdAntiAliased) {
-		/* 
+		/*
 		   gdAntiAliased passed as color: use the much faster, much cheaper
@@ -13,3 +13,3 @@
 		   */
-		gdImageAALine(im, x1, y1, x2, y2, im->AA_color); 
+		gdImageAALine(im, x1, y1, x2, y2, im->AA_color);
 		return;
```

### 2.2. C: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `c23f79e11263f246…` `ext/spl/spl_directory.c`
- t=0: `53510d0dd3be4702…` `ext/spl/spl_directory.c`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -3,3 +3,3 @@
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
```

### 2.3. C: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `08cc43cc0dd4e00a…` `ext/spl/spl_directory.c`
- t=0: `e6a43b31ea4f2ea1…` `ext/spl/spl_directory.c`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -3,3 +3,3 @@
 	spl_filesystem_object *fsobj = zend_object_store_get_object(*object_ptr TSRMLS_CC);
-	
+
 	if (fsobj->u.dir.entry.d_name[0] == '\0' && fsobj->orig_path == NULL) {
@@ -9,3 +9,3 @@
 	}
-	
+
 	return zend_get_std_object_handlers()->get_method(object_ptr, method, method_len, key TSRMLS_CC);
```

### 2.4. C: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `c81567e9522cf1c7…` `xdelta3/xdelta3-test.h`
- t=0: `233a4de0d9a37f6b…` `xdelta3/xdelta3-test.h`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -40,3 +40,3 @@
  	    {
-	      XPR(NT "byte %u (read %u @ %"Q"u) %d != %d\n", 
+	      XPR(NT "byte %u (read %u @ %"Q"u) %d != %d\n",
 		  (int)i, (int)oc, offset, obuf[i], rbuf[i]);
@@ -52,3 +52,3 @@
     fclose (recons);
-    if (diffs != 0) 
+    if (diffs != 0)
       {
```

### 2.5. C++: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `aa08e36f82c89a1a…` `torch/csrc/jit/frontend/script_type_parser.cpp`
- t=0: `8d3b1ec215040c98…` `torch/csrc/jit/frontend/script_type_parser.cpp`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -12,3 +12,3 @@
   // default arguments from standard expressions by piecing together existing
-  // machinery for graph generation, constant propgation, and constant
+  // machinery for graph generation, constant propagation, and constant
   // extraction.
```

### 2.6. Go: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `4833a0d99aae0d32…` `state/services.go`
- t=0: `5ee23387cbb178bf…` `state/services.go`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1 +1 @@
-func (EmptyEvidencePool) AddEvidence(types.Evidence) error              { return nil }
+func (EmptyEvidencePool) AddEvidence(types.Evidence) error                { return nil }
```

### 2.7. Java: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `c848dbdb500b4802…` `src/main/java/org/dom4j/io/SAXReader.java`
- t=0: `9c567988e6ed2d8f…` `src/main/java/org/dom4j/io/SAXReader.java`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,3 +1,3 @@
 public boolean isIncludeInternalDTDDeclarations() {
-        return includeInternalDTDDeclarations;
-    }
+    return includeInternalDTDDeclarations;
+  }
```

### 2.8. Java: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `85afdf9aeeb6933e…` `src/ORG/oclc/oai/server/catalog/ExtendedJDBCOAICatalog.java`
- t=0: `399b1214a64f0ff1…` `src/ORG/oclc/oai/server/catalog/ExtendedJDBCOAICatalog.java`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -11,3 +11,3 @@
             ArrayList sets = new ArrayList();
-            
+
             Connection con = null;
@@ -15,3 +15,3 @@
                 if (debug) System.out.println(setQuery);
-                
+
                 con = startConnection();
@@ -24,5 +24,5 @@
                 int count;
-                
+
 //              if (debug) System.out.println("ExtendedJDBCOAICatalog.listSets: numRows=" + numRows);
-                
+
                 /* load the sets ArrayLists. */
@@ -34,3 +34,3 @@
                 }
-                
+
                 /* decide if you're done */
@@ -39,3 +39,3 @@
                     resumptionResults.put(resumptionId, rs);
-                    
+
                     /*****************************************************************
@@ -49,3 +49,3 @@
                     resumptionTokenSb.append(Integer.toString(numRows));
-                    
+
                     /*****************************************************************
@@ -69,3 +69,3 @@
             }
-            
+
             listSetsMap.put("sets", sets.iterator());
```

### 2.9. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `b5d73fb7db13e0cc…` `assets/js/jquery-ui/external/jquery/jquery.js`
- t=0: `396f9d16cd76afe2…` `assets/js/jquery-ui/external/jquery/jquery.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -4,3 +4,3 @@
 					values[ i ] = arguments.length > 1 ? core_slice.call( arguments ) : value;
-					if( values === progressValues ) {
+					if ( values === progressValues ) {
 						deferred.notifyWith( contexts, values );
```

### 2.10. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `93e0f5fa549b8f73…` `app/webroot/js/action_table.js`
- t=0: `92ac949f2e3220e3…` `app/webroot/js/action_table.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,8 +1,8 @@
 __get_array_from_DOM_row(tr) {
-		var children = tr.children;
-		var array = [];
-		for (var i = 0; i < children.length-1; i++) {
-			array.push(children[i].innerText);
-		}
-		return array;
-	}
+        var children = tr.children;
+        var array = [];
+        for (var i = 0; i < children.length-1; i++) {
+            array.push(children[i].innerText);
+        }
+        return array;
+    }
```

### 2.11. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `40d90a53e0543ebf…` `app/webroot/js/action_table.js`
- t=0: `3e798df7fad9b306…` `app/webroot/js/action_table.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,3 +1,3 @@
 get_data() {
-		return this.data;
-	}
+        return this.data;
+    }
```

### 2.12. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `224958ec3d9274e8…` `app/webroot/js/action_table.js`
- t=0: `b27c04e74d5d5e8c…` `app/webroot/js/action_table.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,3 +1,3 @@
 __data_already_exists(data) {
-		return this.__find_array_index(data, this.data) >= 0;
-	}
+        return this.__find_array_index(data, this.data) >= 0;
+    }
```

### 2.13. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `7d3d4d3b4257409e…` `test/xoauth2/server.js`
- t=0: `fdf9c49910f03f8a…` `test/xoauth2/server.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,2 +1,2 @@
-OAuthServer.prototype.generateAccessToken = function(refreshToken) {
+OAuthServer.prototype.generateAccessToken = function (refreshToken) {
     let username = this.tokens[refreshToken];
```

### 2.14. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `2fb58227fcb3973a…` `scripts/functions.imgmappin.admin.js`
- t=0: `c6dfb814bc09fbbd…` `scripts/functions.imgmappin.admin.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,10 +1,10 @@
-retrieveMapPoints : function (){
-            
+retrieveMapPoints: function() {
+
             busy();
-            
+
             var data = {
                 action: 'e2m_img_retrieve_map_points',
-                MapID : $mapID
+                MapID: $mapID
             };
-            
+
             //clear all controls for blank slate
@@ -12,3 +12,3 @@
             easy2map_imgmap_functions.disableHover();
-        
+
             jQuery.ajax({
@@ -17,15 +17,18 @@
                 data: data,
-                dataType : 'json',
+                dataType: 'json',
                 success: function(returnData) {
-                    
+
                     jQuery('#tblMapMarkers').show().find('tr').remove();
                     jQuery('#Easy2MapSliderParent').show().find('li').remove();
-                    
+
                     var noPinsFound = false;
-                    
-                    if (typeof returnData == "undefined" || typeof returnData == "null") noPinsFound = true;
-                    if (!returnData) noPinsFound = true;
-                    if (returnData.length == 0)  noPinsFound = true;
-                    
-                    if (noPinsFound){
+
+                    if (typeof returnData == "undefined" || typeof returnData == "null")
+                        noPinsFound = true;
+                    if (!returnData)
+                        noPinsFound = true;
+                    if (returnData.length == 0)
+                        noPinsFound = true;
+
+                    if (noPinsFound) {
                         //if no pins are found, prompt the user to add a new pin
@@ -41,36 +44,37 @@
                     }
-                    
-                    if ($markersArray) $markersArray.length = 0;
+
+                    if ($markersArray)
+                        $markersArray.length = 0;
                     clearPinArray();
-                                                           
-                    for(var t = 0; t < returnData.length; t++){
-                        
+
+                    for (var t = 0; t < returnData.length; t++) {
+
                         var arrLatLng = replaceAll(replaceAll(replaceAll(returnData[t].LatLong, ' ', ''), '(', ''), ')', '').split(',');
                         var objMapPoint = {
-                            lattitude : arrLatLng[0],
-                            longitude : arrLatLng[1],
-                            ID : returnData[t].ID,
-                            title : returnData[t].Title,
-                            icon : returnData[t].ImageURL,
-                            settings : returnData[t].Settings,
-                            small : returnData[t].PinImageSmall,
-                            medium : returnData[t].PinImageMedium,
-                            large : returnData[t].PinImageLarge,
-                            pinhtml : returnData[t].MapPinHTML,
-                            pintext : returnData[t].MapPinText
+                            lattitude: arrLatLng[0],
+                            longitude: arrLatLng[1],
+                            ID: returnData[t].ID,
+                            title: returnData[t].Title,
+                            icon: returnData[t].ImageURL,
+                            settings: returnData[t].Settings,
+                            small: returnData[t].PinImageSmall,
+                            medium: returnData[t].PinImageMedium,
+                            large: returnData[t].PinImageLarge,
+                            pinhtml: returnData[t].MapPinHTML,
+                            pintext: returnData[t].MapPinText
                         }
-                        
+
                         $markersArray.push(new listedMapPin(objMapPoint));
                     }
-                    
+
                     var sliderImages = [];
-                    for (var i = 0; i < $markersArray.length; i++){
-                        
+                    for (var i = 0; i < $markersArray.length; i++) {
+
                         var selectedListItem = $markersArray[i].pinDetails;
                         addPinToMap(selectedListItem);
-                        
-                        if (document.getElementById('Easy2MapSliderParent')){
+
+                        if (document.getElementById('Easy2MapSliderParent')) {
                             var li = document.createElement('li');
                             li.className = "easy2mapslide";
-                            
+
                             li.setAttribute("sliderID", selectedListItem.ID);
@@ -80,6 +84,6 @@
                         }
-                       
+
                         var tr = document.createElement('tr');
                         document.getElementById('tblMapMarkers').appendChild(tr);
-                       
+
                         var imageTd = document.createElement('td');
@@ -95,3 +99,3 @@
                         imageTd.appendChild(image);
-                        
+
                         var imageTd2 = document.createElement('td');
@@ -108,3 +112,3 @@
                         imageTd2.style.width = '60%';
-                        
+
                         var editTd = document.createElement('td');
@@ -120,3 +124,3 @@
                         editTd.appendChild(editLink);
-                        
+
                         tr.appendChild(imageTd);
@@ -124,7 +128,7 @@
                         tr.appendChild(editTd);
-                       
+
                     }
-                    
-                    if (sliderImages.length > 0){
-                        jQuery.preloadImages(sliderImages, function initSliderImages(){
+
+                    if (sliderImages.length > 0) {
+                        jQuery.preloadImages(sliderImages, function initSliderImages() {
                             jQuery('#easy2mapslider').imgSlider(sliderImages);
@@ -132,9 +136,9 @@
                     }
-           
... (cắt bớt)
```

### 2.15. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `cd2ee56bdeeee4ed…` `js/hdflvscript.js`
- t=0: `3f17e1bdcde91bcc…` `js/hdflvscript.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,2 +1,2 @@
-function  setVideoStatusOff(videoId , status ,flag )  //click on status image then it exe
+function setVideoStatusOff(videoId, status, flag) //click on status image then it exe
 {
@@ -5,33 +5,28 @@
 	var xmlhttp;
-	var url="../wp-content/plugins/contus-hd-flv-player/process-sortable.php";
+	var url = "../wp-content/plugins/contus-hd-flv-player/process-sortable.php";
 	//var statusImgPath = document.getElementById('imagepath').value;
-	if (window.XMLHttpRequest)
-	  {// code for IE7+, Firefox, Chrome, Opera, Safari
-	  xmlhttp=new XMLHttpRequest();
-	  }
-	else
-	  {// code for IE6, IE5
-	  xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
-	  }
-	xmlhttp.onreadystatechange=function()
-	  {
-	  if (xmlhttp.readyState==4 && xmlhttp.status==200)
-	    {
-		 imgName  = (xmlhttp.responseText);
-				
-		  //alert(imgName);
-		 // alert(  document.getElementById('status'+videoId).innerHTML);
-		 
-	    document.getElementById('status'+videoId).innerHTML= imgName;
-	    }
-	  }
-	if(flag){
-	//	alert( url+'?changeplaylistStatus=1&videoId='+videoId+'&status='+status);
-		xmlhttp.open("GET", url+'?changeplaylistStatus=1&videoId='+videoId+'&status='+status  ,true);//for playlist status
+	if (window.XMLHttpRequest) {// code for IE7+, Firefox, Chrome, Opera, Safari
+		xmlhttp = new XMLHttpRequest();
+	} else {// code for IE6, IE5
+		xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
 	}
-	else{
-		xmlhttp.open("GET", url+'?changeVideoStatus=1&videoId='+videoId+'&status='+status  ,true); //for video status
-	}	
-	
-	
+	xmlhttp.onreadystatechange = function() {
+		if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
+			imgName = (xmlhttp.responseText);
+
+			//alert(imgName);
+			// alert(  document.getElementById('status'+videoId).innerHTML);
+
+			document.getElementById('status' + videoId).innerHTML = imgName;
+		}
+	}
+	if (flag) {
+		//	alert( url+'?changeplaylistStatus=1&videoId='+videoId+'&status='+status);
+		xmlhttp.open("GET", url + '?changeplaylistStatus=1&videoId=' + videoId
+				+ '&status=' + status, true);//for playlist status
+	} else {
+		xmlhttp.open("GET", url + '?changeVideoStatus=1&videoId=' + videoId
+				+ '&status=' + status, true); //for video status
+	}
+
 	xmlhttp.send();
```

### 2.16. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `9e39921a6487cebf…` `js/DivControl.js`
- t=0: `16b90f869043bfcb…` `js/DivControl.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,5 +1,3 @@
-function prim_showdiv()
-{
-    if (document.getElementById)
-    {
+function prim_showdiv() {
+    if (document.getElementById) {
         document.getElementById("prim_hideShow").style.display = "block";
```

### 2.17. JavaScript: nhóm 3 đơn vị (1 t=1, 2 t=0)

- t=1: `8fc2186cf25e6293…` `src/main/webapp/js/grapheditor/Menus.js`
- t=0: `1eb8d2fbc6afa731…` `src/main/webapp/js/grapheditor/Menus.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -8,3 +8,3 @@
 	this.customFontSizes = [];
-
+	
 	this.put('fontFamily', new Menu(mxUtils.bind(this, function(menu, parent)
```

### 2.18. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `a2aebd2d84de274f…` `js/DivControl.js`
- t=0: `cd43b27dfd3c7ff5…` `js/DivControl.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,3 +1,2 @@
-function hide_filter_modal()
-{
+function hide_filter_modal() {
     window.$('#modal_filter_edit').modal('toggle');
```

### 2.19. JavaScript: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `794a424342cba8ad…` `simple-git/src/git.js`
- t=0: `3c5927ae00b046e7…` `simple-git/src/git.js`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -1,2 +1,2 @@
-Git.prototype.applyPatch = function(patches) {
+Git.prototype.applyPatch = function (patches) {
    const task = !filterStringOrStringArray(patches)
```

### 2.20. Python: nhóm 2 đơn vị (1 t=1, 1 t=0)

- t=1: `ff6dcad03e3bed3c…` `tastypie/serializers.py`
- t=0: `ab6c2ef00871cf16…` `tastypie/serializers.py`
- đánh giá: 

```diff
--- target=1
+++ target=0
@@ -3,3 +3,3 @@
         Given a format, attempts to determine the correct MIME type.
-        
+
         If not available on the current ``Serializer``, returns
```

