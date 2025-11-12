```diff
diff --git a/common/bcp47/timezone.xml b/common/bcp47/timezone.xml
index b173ad4c..c3a9a0d0 100644
--- a/common/bcp47/timezone.xml
+++ b/common/bcp47/timezone.xml
@@ -130,6 +130,7 @@ For terms of use, see http://www.unicode.org/copyright.html
             <type name="chzrh" description="Zurich, Switzerland" alias="Europe/Zurich"/>
             <type name="ciabj" description="Abidjan, Côte d'Ivoire" alias="Africa/Abidjan"/>
             <type name="ckrar" description="Rarotonga, Cook Islands" alias="Pacific/Rarotonga"/>
+            <type name="clcxq" description="Aysén Region, Chile" alias="America/Coyhaique" since="48"/>
             <type name="clipc" description="Easter Island, Chile" alias="Pacific/Easter Chile/EasterIsland"/>
             <type name="clpuq" description="Punta Arenas, Chile" alias="America/Punta_Arenas" since="31"/>
             <type name="clscl" description="Santiago, Chile" alias="America/Santiago Chile/Continental"/>
diff --git a/common/main/en.xml b/common/main/en.xml
index 467200ab..9397a64e 100644
--- a/common/main/en.xml
+++ b/common/main/en.xml
@@ -3218,6 +3218,487 @@ annotations.
 				</dateTimeFormats>
 			</calendar>
 			<calendar type="japanese">
+			<!-- Android patch (b/416368632) -->
+				<eras>
+					<eraAbbr>
+						<era type="0">Taika</era>
+						<era type="1">Hakuchi</era>
+						<era type="2">Hakuhō</era>
+						<era type="3">Shuchō</era>
+						<era type="4">Taihō</era>
+						<era type="5">Keiun</era>
+						<era type="6">Wadō</era>
+						<era type="7">Reiki</era>
+						<era type="8">Yōrō</era>
+						<era type="9">Jinki</era>
+						<era type="10">Tenpyō</era>
+						<era type="11">Tenpyō-kanpō</era>
+						<era type="12">Tenpyō-shōhō</era>
+						<era type="13">Tenpyō-hōji</era>
+						<era type="14">Tenpyō-jingo</era>
+						<era type="15">Jingo-keiun</era>
+						<era type="16">Hōki</era>
+						<era type="17">Ten’ō</era>
+						<era type="18">Enryaku</era>
+						<era type="19">Daidō</era>
+						<era type="20">Kōnin</era>
+						<era type="21">Tenchō</era>
+						<era type="22">Jōwa</era>
+						<era type="23">Kashō</era>
+						<era type="24">Ninju</era>
+						<era type="25">Saikō</era>
+						<era type="26">Ten’an</era>
+						<era type="27">Jōgan</era>
+						<era type="28">Gangyō</era>
+						<era type="29">Ninna</era>
+						<era type="30">Kanpyō</era>
+						<era type="31">Shōtai</era>
+						<era type="32">Engi</era>
+						<era type="33">Enchō</era>
+						<era type="34">Jōhei</era>
+						<era type="35">Tengyō</era>
+						<era type="36">Tenryaku</era>
+						<era type="37">Tentoku</era>
+						<era type="38">Ōwa</era>
+						<era type="39">Kōhō</era>
+						<era type="40">Anna</era>
+						<era type="41">Tenroku</era>
+						<era type="42">Ten’en</era>
+						<era type="43">Jōgen</era>
+						<era type="44">Tengen</era>
+						<era type="45">Eikan</era>
+						<era type="46">Kanna</era>
+						<era type="47">Eien</era>
+						<era type="48">Eiso</era>
+						<era type="49">Shōryaku</era>
+						<era type="50">Chōtoku</era>
+						<era type="51">Chōhō</era>
+						<era type="52">Kankō</era>
+						<era type="53">Chōwa</era>
+						<era type="54">Kannin</era>
+						<era type="55">Jian</era>
+						<era type="56">Manju</era>
+						<era type="57">Chōgen</era>
+						<era type="58">Chōryaku</era>
+						<era type="59">Chōkyū</era>
+						<era type="60">Kantoku</era>
+						<era type="61">Eishō</era>
+						<era type="62">Tengi</era>
+						<era type="63">Kōhei</era>
+						<era type="64">Jiryaku</era>
+						<era type="65">Enkyū</era>
+						<era type="66">Jōhō</era>
+						<era type="67">Jōryaku</era>
+						<era type="68">Eihō</era>
+						<era type="69">Ōtoku</era>
+						<era type="70">Kanji</era>
+						<era type="71">Kahō</era>
+						<era type="72">Eichō</era>
+						<era type="73">Jōtoku</era>
+						<era type="74">Kōwa</era>
+						<era type="75">Chōji</era>
+						<era type="76">Kajō</era>
+						<era type="77">Tennin</era>
+						<era type="78">Ten’ei</era>
+						<era type="79">Eikyū</era>
+						<era type="80">Gen’ei</era>
+						<era type="81">Hōan</era>
+						<era type="82">Tenji</era>
+						<era type="83">Daiji</era>
+						<era type="84">Tenshō</era>
+						<era type="85">Chōshō</era>
+						<era type="86">Hōen</era>
+						<era type="87">Eiji</era>
+						<era type="88">Kōji</era>
+						<era type="89">Ten’yō</era>
+						<era type="90">Kyūan</era>
+						<era type="91">Ninpei</era>
+						<era type="92">Kyūju</era>
+						<era type="93">Hōgen</era>
+						<era type="94">Heiji</era>
+						<era type="95">Eiryaku</era>
+						<era type="96">Ōhō</era>
+						<era type="97">Chōkan</era>
+						<era type="98">Eiman</era>
+						<era type="99">Nin’an</era>
+						<era type="100">Kaō</era>
+						<era type="101">Jōan</era>
+						<era type="102">Angen</era>
+						<era type="103">Jishō</era>
+						<era type="104">Yōwa</era>
+						<era type="105">Juei</era>
+						<era type="106">Genryaku</era>
+						<era type="107">Bunji</era>
+						<era type="108">Kenkyū</era>
+						<era type="109">Shōji</era>
+						<era type="110">Kennin</era>
+						<era type="111">Genkyū</era>
+						<era type="112">Ken’ei</era>
+						<era type="113">Jōgen</era>
+						<era type="114">Kenryaku</era>
+						<era type="115">Kempo</era>
+						<era type="116">Jōkyū</era>
+						<era type="117">Jōō</era>
+						<era type="118">Gennin</era>
+						<era type="119">Karoku</era>
+						<era type="120">Antei</era>
+						<era type="121">Kangi</era>
+						<era type="122">Jōei</era>
+						<era type="123">Tenpuku</era>
+						<era type="124">Bunryaku</era>
+						<era type="125">Katei</era>
+						<era type="126">Ryakunin</era>
+						<era type="127">En’ō</era>
+						<era type="128">Ninji</era>
+						<era type="129">Kangen</era>
+						<era type="130">Hōji</era>
+						<era type="131">Kenchō</era>
+						<era type="132">Kōgen</era>
+						<era type="133">Shōka</era>
+						<era type="134">Shōgen</era>
+						<era type="135">Bun’ō</era>
+						<era type="136">Kōchō</era>
+						<era type="137">Bun’ei</era>
+						<era type="138">Kenji</era>
+						<era type="139">Kōan</era>
+						<era type="140">Shōō</era>
+						<era type="141">Einin</era>
+						<era type="142">Shōan</era>
+						<era type="143">Kengen</era>
+						<era type="144">Kagen</era>
+						<era type="145">Tokuji</era>
+						<era type="146">Enkyō</era>
+						<era type="147">Ōchō</era>
+						<era type="148">Shōwa</era>
+						<era type="149">Bunpō</era>
+						<era type="150">Gen’ō</era>
+						<era type="151">Genkō</era>
+						<era type="152">Shōchū</era>
+						<era type="153">Karyaku</era>
+						<era type="154">Gentoku</era>
+						<era type="155">Genkō</era>
+						<era type="156">Kenmu</era>
+						<era type="157">Engen</era>
+						<era type="158">Kōkoku</era>
+						<era type="159">Shōhei</era>
+						<era type="160">Kentoku</era>
+						<era type="161">Bunchū</era>
+						<era type="162">Tenju</era>
+						<era type="163">Kōryaku</era>
+						<era type="164">Kōwa</era>
+						<era type="165">Genchū</era>
+						<era type="166">Shitoku</era>
+						<era type="167">Kakei</era>
+						<era type="168">Kōō</era>
+						<era type="169">Meitoku</era>
+						<era type="170">Ōei</era>
+						<era type="171">Shōchō</era>
+						<era type="172">Eikyō</era>
+						<era type="173">Kakitsu</era>
+						<era type="174">Bun’an</era>
+						<era type="175">Hōtoku</era>
+						<era type="176">Kyōtoku</era>
+						<era type="177">Kōshō</era>
+						<era type="178">Chōroku</era>
+						<era type="179">Kanshō</era>
+						<era type="180">Bunshō</era>
+						<era type="181">Ōnin</era>
+						<era type="182">Bunmei</era>
+						<era type="183">Chōkyō</era>
+						<era type="184">Entoku</era>
+						<era type="185">Meiō</era>
+						<era type="186">Bunki</era>
+						<era type="187">Eishō</era>
+						<era type="188">Daiei</era>
+						<era type="189">Kyōroku</era>
+						<era type="190">Tenbun</era>
+						<era type="191">Kōji</era>
+						<era type="192">Eiroku</era>
+						<era type="193">Genki</era>
+						<era type="194">Tenshō</era>
+						<era type="195">Bunroku</era>
+						<era type="196">Keichō</era>
+						<era type="197">Genna</era>
+						<era type="198">Kan’ei</era>
+						<era type="199">Shōhō</era>
+						<era type="200">Keian</era>
+						<era type="201">Jōō</era>
+						<era type="202">Meireki</era>
+						<era type="203">Manji</era>
+						<era type="204">Kanbun</era>
+						<era type="205">Enpō</era>
+						<era type="206">Tenna</era>
+						<era type="207">Jōkyō</era>
+						<era type="208">Genroku</era>
+						<era type="209">Hōei</era>
+						<era type="210">Shōtoku</era>
+						<era type="211">Kyōhō</era>
+						<era type="212">Genbun</era>
+						<era type="213">Kanpō</era>
+						<era type="214">Enkyō</era>
+						<era type="215">Kan’en</era>
+						<era type="216">Hōreki</era>
+						<era type="217">Meiwa</era>
+						<era type="218">An’ei</era>
+						<era type="219">Tenmei</era>
+						<era type="220">Kansei</era>
+						<era type="221">Kyōwa</era>
+						<era type="222">Bunka</era>
+						<era type="223">Bunsei</era>
+						<era type="224">Tenpō</era>
+						<era type="225">Kōka</era>
+						<era type="226">Kaei</era>
+						<era type="227">Ansei</era>
+						<era type="228">Man’en</era>
+						<era type="229">Bunkyū</era>
+						<era type="230">Genji</era>
+						<era type="231">Keiō</era>
+						<era type="232">Meiji</era>
+						<era type="233">Taishō</era>
+						<era type="234">Shōwa</era>
+						<era type="235">Heisei</era>
+						<era type="236">Reiwa</era>
+					</eraAbbr>
+					<eraNarrow>
+						<era type="0">Taika</era>
+						<era type="1">Hakuchi</era>
+						<era type="2">Hakuhō</era>
+						<era type="3">Shuchō</era>
+						<era type="4">Taihō</era>
+						<era type="5">Keiun</era>
+						<era type="6">Wadō</era>
+						<era type="7">Reiki</era>
+						<era type="8">Yōrō</era>
+						<era type="9">Jinki</era>
+						<era type="10">Tenpyō</era>
+						<era type="11">Tenpyō-kanpō</era>
+						<era type="12">Tenpyō-shōhō</era>
+						<era type="13">Tenpyō-hōji</era>
+						<era type="14">Tenpyō-jingo</era>
+						<era type="15">Jingo-keiun</era>
+						<era type="16">Hōki</era>
+						<era type="17">Ten’ō</era>
+						<era type="18">Enryaku</era>
+						<era type="19">Daidō</era>
+						<era type="20">Kōnin</era>
+						<era type="21">Tenchō</era>
+						<era type="22">Jōwa</era>
+						<era type="23">Kashō</era>
+						<era type="24">Ninju</era>
+						<era type="25">Saikō</era>
+						<era type="26">Ten’an</era>
+						<era type="27">Jōgan</era>
+						<era type="28">Gangyō</era>
+						<era type="29">Ninna</era>
+						<era type="30">Kanpyō</era>
+						<era type="31">Shōtai</era>
+						<era type="32">Engi</era>
+						<era type="33">Enchō</era>
+						<era type="34">Jōhei</era>
+						<era type="35">Tengyō</era>
+						<era type="36">Tenryaku</era>
+						<era type="37">Tentoku</era>
+						<era type="38">Ōwa</era>
+						<era type="39">Kōhō</era>
+						<era type="40">Anna</era>
+						<era type="41">Tenroku</era>
+						<era type="42">Ten’en</era>
+						<era type="43">Jōgen</era>
+						<era type="44">Tengen</era>
+						<era type="45">Eikan</era>
+						<era type="46">Kanna</era>
+						<era type="47">Eien</era>
+						<era type="48">Eiso</era>
+						<era type="49">Shōryaku</era>
+						<era type="50">Chōtoku</era>
+						<era type="51">Chōhō</era>
+						<era type="52">Kankō</era>
+						<era type="53">Chōwa</era>
+						<era type="54">Kannin</era>
+						<era type="55">Jian</era>
+						<era type="56">Manju</era>
+						<era type="57">Chōgen</era>
+						<era type="58">Chōryaku</era>
+						<era type="59">Chōkyū</era>
+						<era type="60">Kantoku</era>
+						<era type="61">Eishō</era>
+						<era type="62">Tengi</era>
+						<era type="63">Kōhei</era>
+						<era type="64">Jiryaku</era>
+						<era type="65">Enkyū</era>
+						<era type="66">Jōhō</era>
+						<era type="67">Jōryaku</era>
+						<era type="68">Eihō</era>
+						<era type="69">Ōtoku</era>
+						<era type="70">Kanji</era>
+						<era type="71">Kahō</era>
+						<era type="72">Eichō</era>
+						<era type="73">Jōtoku</era>
+						<era type="74">Kōwa</era>
+						<era type="75">Chōji</era>
+						<era type="76">Kajō</era>
+						<era type="77">Tennin</era>
+						<era type="78">Ten’ei</era>
+						<era type="79">Eikyū</era>
+						<era type="80">Gen’ei</era>
+						<era type="81">Hōan</era>
+						<era type="82">Tenji</era>
+						<era type="83">Daiji</era>
+						<era type="84">Tenshō</era>
+						<era type="85">Chōshō</era>
+						<era type="86">Hōen</era>
+						<era type="87">Eiji</era>
+						<era type="88">Kōji</era>
+						<era type="89">Ten’yō</era>
+						<era type="90">Kyūan</era>
+						<era type="91">Ninpei</era>
+						<era type="92">Kyūju</era>
+						<era type="93">Hōgen</era>
+						<era type="94">Heiji</era>
+						<era type="95">Eiryaku</era>
+						<era type="96">Ōhō</era>
+						<era type="97">Chōkan</era>
+						<era type="98">Eiman</era>
+						<era type="99">Nin’an</era>
+						<era type="100">Kaō</era>
+						<era type="101">Jōan</era>
+						<era type="102">Angen</era>
+						<era type="103">Jishō</era>
+						<era type="104">Yōwa</era>
+						<era type="105">Juei</era>
+						<era type="106">Genryaku</era>
+						<era type="107">Bunji</era>
+						<era type="108">Kenkyū</era>
+						<era type="109">Shōji</era>
+						<era type="110">Kennin</era>
+						<era type="111">Genkyū</era>
+						<era type="112">Ken’ei</era>
+						<era type="113">Jōgen</era>
+						<era type="114">Kenryaku</era>
+						<era type="115">Kempo</era>
+						<era type="116">Jōkyū</era>
+						<era type="117">Jōō</era>
+						<era type="118">Gennin</era>
+						<era type="119">Karoku</era>
+						<era type="120">Antei</era>
+						<era type="121">Kangi</era>
+						<era type="122">Jōei</era>
+						<era type="123">Tenpuku</era>
+						<era type="124">Bunryaku</era>
+						<era type="125">Katei</era>
+						<era type="126">Ryakunin</era>
+						<era type="127">En’ō</era>
+						<era type="128">Ninji</era>
+						<era type="129">Kangen</era>
+						<era type="130">Hōji</era>
+						<era type="131">Kenchō</era>
+						<era type="132">Kōgen</era>
+						<era type="133">Shōka</era>
+						<era type="134">Shōgen</era>
+						<era type="135">Bun’ō</era>
+						<era type="136">Kōchō</era>
+						<era type="137">Bun’ei</era>
+						<era type="138">Kenji</era>
+						<era type="139">Kōan</era>
+						<era type="140">Shōō</era>
+						<era type="141">Einin</era>
+						<era type="142">Shōan</era>
+						<era type="143">Kengen</era>
+						<era type="144">Kagen</era>
+						<era type="145">Tokuji</era>
+						<era type="146">Enkyō</era>
+						<era type="147">Ōchō</era>
+						<era type="148">Shōwa</era>
+						<era type="149">Bunpō</era>
+						<era type="150">Gen’ō</era>
+						<era type="151">Genkō</era>
+						<era type="152">Shōchū</era>
+						<era type="153">Karyaku</era>
+						<era type="154">Gentoku</era>
+						<era type="155">Genkō</era>
+						<era type="156">Kenmu</era>
+						<era type="157">Engen</era>
+						<era type="158">Kōkoku</era>
+						<era type="159">Shōhei</era>
+						<era type="160">Kentoku</era>
+						<era type="161">Bunchū</era>
+						<era type="162">Tenju</era>
+						<era type="163">Kōryaku</era>
+						<era type="164">Kōwa</era>
+						<era type="165">Genchū</era>
+						<era type="166">Shitoku</era>
+						<era type="167">Kakei</era>
+						<era type="168">Kōō</era>
+						<era type="169">Meitoku</era>
+						<era type="170">Ōei</era>
+						<era type="171">Shōchō</era>
+						<era type="172">Eikyō</era>
+						<era type="173">Kakitsu</era>
+						<era type="174">Bun’an</era>
+						<era type="175">Hōtoku</era>
+						<era type="176">Kyōtoku</era>
+						<era type="177">Kōshō</era>
+						<era type="178">Chōroku</era>
+						<era type="179">Kanshō</era>
+						<era type="180">Bunshō</era>
+						<era type="181">Ōnin</era>
+						<era type="182">Bunmei</era>
+						<era type="183">Chōkyō</era>
+						<era type="184">Entoku</era>
+						<era type="185">Meiō</era>
+						<era type="186">Bunki</era>
+						<era type="187">Eishō</era>
+						<era type="188">Daiei</era>
+						<era type="189">Kyōroku</era>
+						<era type="190">Tenbun</era>
+						<era type="191">Kōji</era>
+						<era type="192">Eiroku</era>
+						<era type="193">Genki</era>
+						<era type="194">Tenshō</era>
+						<era type="195">Bunroku</era>
+						<era type="196">Keichō</era>
+						<era type="197">Genna</era>
+						<era type="198">Kan’ei</era>
+						<era type="199">Shōhō</era>
+						<era type="200">Keian</era>
+						<era type="201">Jōō</era>
+						<era type="202">Meireki</era>
+						<era type="203">Manji</era>
+						<era type="204">Kanbun</era>
+						<era type="205">Enpō</era>
+						<era type="206">Tenna</era>
+						<era type="207">Jōkyō</era>
+						<era type="208">Genroku</era>
+						<era type="209">Hōei</era>
+						<era type="210">Shōtoku</era>
+						<era type="211">Kyōhō</era>
+						<era type="212">Genbun</era>
+						<era type="213">Kanpō</era>
+						<era type="214">Enkyō</era>
+						<era type="215">Kan’en</era>
+						<era type="216">Hōreki</era>
+						<era type="217">Meiwa</era>
+						<era type="218">An’ei</era>
+						<era type="219">Tenmei</era>
+						<era type="220">Kansei</era>
+						<era type="221">Kyōwa</era>
+						<era type="222">Bunka</era>
+						<era type="223">Bunsei</era>
+						<era type="224">Tenpō</era>
+						<era type="225">Kōka</era>
+						<era type="226">Kaei</era>
+						<era type="227">Ansei</era>
+						<era type="228">Man’en</era>
+						<era type="229">Bunkyū</era>
+						<era type="230">Genji</era>
+						<era type="231">Keiō</era>
+  						<era type="232">M</era>
+						<era type="233">T</era>
+						<era type="234">S</era>
+						<era type="235">H</era>
+						<era type="236">R</era>
+					</eraNarrow>
+				</eras>
 				<dateFormats>
 					<dateFormatLength type="full">
 						<dateFormat>
@@ -3244,6 +3725,219 @@ annotations.
 						</dateFormat>
 					</dateFormatLength>
 				</dateFormats>
+				<dateTimeFormats>
+					<dateTimeFormatLength type="full">
+						<dateTimeFormat>
+							<pattern>{1} 'at' {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1} 'at' {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<dateTimeFormatLength type="long">
+						<dateTimeFormat>
+							<pattern>{1} 'at' {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1} 'at' {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<dateTimeFormatLength type="medium">
+						<dateTimeFormat>
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<dateTimeFormatLength type="short">
+						<dateTimeFormat>
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<availableFormats>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">M/d/y GGGGG</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="H">HH</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">M/d</dateFormatItem>
+						<dateFormatItem id="MEd">E, M/d</dateFormatItem>
+						<dateFormatItem id="MEEEEd">EEEE, M/d</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="ms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">M/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMd">M/d/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">E, M/d/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMM">MM y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>{0} – {1}</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d – d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="G">y G – y G</greatestDifference>
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyM">
+							<greatestDifference id="G">M/y GGGGG – M/y GGGGG</greatestDifference>
+							<greatestDifference id="M">M/y – M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/y – M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="G">M/d/y GGGGG – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/d/y – M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="G">E, M/d/y GGGGG – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMM">
+							<greatestDifference id="G">MMM y G – MMM y G</greatestDifference>
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="G">MMM d, y G – MMM d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="G">E, MMM d, y G – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">HH – HH</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">HH:mm – HH:mm</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">HH:mm – HH:mm v</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">HH – HH v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M – M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">M/d – M/d</greatestDifference>
+							<greatestDifference id="M">M/d – M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E, M/d – E, M/d</greatestDifference>
+							<greatestDifference id="M">E, M/d – E, M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">MMM d – d</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">M/y – M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/y – M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/d/y – M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M">MMMM – MMMM y G</greatestDifference>
+							<greatestDifference id="y">MMMM y – MMMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
 			</calendar>
 			<calendar type="roc">
 				<eras>
@@ -3252,6 +3946,213 @@ annotations.
 						<era type="1">Minguo</era>
 					</eraAbbr>
 				</eras>
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>M/d/y GGGGG</pattern>
+							<datetimeSkeleton>GGGGGyMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Bh">h B</dateFormatItem>
+						<dateFormatItem id="Bhm">h:mm B</dateFormatItem>
+						<dateFormatItem id="Bhms">h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">M/d/y G</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="H">HH</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">HH:mm</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">M/d</dateFormatItem>
+						<dateFormatItem id="MEd">E, M/d</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">M/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMd">M/d/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">E, M/d/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>{0} – {1}</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d – d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="G">y G – y G</greatestDifference>
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyM">
+							<greatestDifference id="G">M/y GGGGG – M/y GGGGG</greatestDifference>
+							<greatestDifference id="M">M/y – M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/y – M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="G">M/d/y GGGGG – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/d/y – M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="G">E, M/d/y GGGGG – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMM">
+							<greatestDifference id="G">MMM y G – MMM y G</greatestDifference>
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="G">MMM d, y G – MMM d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="G">E, MMM d, y G – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">HH – HH</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">HH:mm – HH:mm</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">HH:mm – HH:mm v</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">HH – HH v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M – M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">M/d – M/d</greatestDifference>
+							<greatestDifference id="M">M/d – M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E, M/d – E, M/d</greatestDifference>
+							<greatestDifference id="M">E, M/d – E, M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">MMM d – d</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">M/y – M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/y – M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">M/d/y – M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/d/y – M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, M/d/y – E, M/d/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M">MMMM – MMMM y G</greatestDifference>
+							<greatestDifference id="y">MMMM y – MMMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
 			</calendar>
 		</calendars>
 		<fields>
diff --git a/common/main/en_001.xml b/common/main/en_001.xml
index acbed877..107e2891 100644
--- a/common/main/en_001.xml
+++ b/common/main/en_001.xml
@@ -508,6 +508,268 @@ Warnings: All cp values have U+FE0F characters removed. See /annotationsDerived/
 					</availableFormats>
 				</dateTimeFormats>
 			</calendar>
+			<calendar type="japanese">
+			<!-- Android patch (b/416368632) -->
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, d MMMM y G</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>d MMMM y G</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>d MMM y G</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>dd/MM/y GGGGG</pattern>
+							<datetimeSkeleton>GGGGGyMMdd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Ed">E d</dateFormatItem>
+						<dateFormatItem id="GyMd">dd/MM/y GGGGG</dateFormatItem>
+						<dateFormatItem id="GyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, d MMM y G</dateFormatItem>
+						<dateFormatItem id="M">LL</dateFormatItem>
+						<dateFormatItem id="Md">dd/MM</dateFormatItem>
+						<dateFormatItem id="MEd">E, dd/MM</dateFormatItem>
+						<dateFormatItem id="MMMd">d MMM</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, d MMM</dateFormatItem>
+						<dateFormatItem id="MMMMd">d MMMM</dateFormatItem>
+						<dateFormatItem id="yyyyM">MM/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMd">dd/MM/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">E, dd/MM/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, d MMM y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d–d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="y">y–y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="G">dd/MM/y GGGGG – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="G">E, dd/MM/y GGGGG – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">d–d MMM y G</greatestDifference>
+							<greatestDifference id="G">d MMM y G – d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="G">E, d MMM y G – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M–M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">dd/MM – dd/MM</greatestDifference>
+							<greatestDifference id="M">dd/MM – dd/MM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E dd/MM – E dd/MM</greatestDifference>
+							<greatestDifference id="M">E dd/MM – E dd/MM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">d–d MMM</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E d – E d MMM</greatestDifference>
+							<greatestDifference id="M">E d MMM – E d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y–y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">MM/y – MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">MM/y – MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">d–d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, d – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="roc">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, d MMMM y G</pattern>
+							<datetimeSkeleton>GyMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>d MMMM y G</pattern>
+							<datetimeSkeleton>GyMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>d MMM y G</pattern>
+							<datetimeSkeleton>GyMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>dd/MM/y GGGGG</pattern>
+							<datetimeSkeleton>GGGGGyMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">dd/MM/y G</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, d MMM y G</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">dd/MM</dateFormatItem>
+						<dateFormatItem id="MEd">E, dd/MM</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">d MMM</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, d MMM</dateFormatItem>
+						<dateFormatItem id="MMMMd">d MMMM</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">MM/y G</dateFormatItem>
+						<dateFormatItem id="yyyyMd">dd/MM/y G</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">E, dd/MM/y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, d MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d–d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="y">y–y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="G">dd/MM/y GGGGG – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="G">E, dd/MM/y GGGGG – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">d–d MMM y G</greatestDifference>
+							<greatestDifference id="G">d MMM y G – d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="G">E, d MMM y G – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M–M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">dd/MM – dd/MM</greatestDifference>
+							<greatestDifference id="M">dd/MM – dd/MM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E dd/MM – E dd/MM</greatestDifference>
+							<greatestDifference id="M">E dd/MM – E dd/MM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">d–d MMM</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E d – E d MMM</greatestDifference>
+							<greatestDifference id="M">E d MMM – E d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y–y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">MM/y – MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">MM/y – MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">dd/MM/y – dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, dd/MM/y – E, dd/MM/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">d–d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, d – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
 		</calendars>
 		<fields>
 			<field type="year-short">
diff --git a/common/main/en_BD.xml b/common/main/en_BD.xml
new file mode 100644
index 00000000..ee7410ba
--- /dev/null
+++ b/common/main/en_BD.xml
@@ -0,0 +1,181 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2024 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="BD"/>
+	</identity>
+  <numbers>
+		<defaultNumberingSystem>↑↑↑</defaultNumberingSystem>
+		<otherNumberingSystems>
+			<native>↑↑↑</native>
+		</otherNumberingSystems>
+		<minimumGroupingDigits>↑↑↑</minimumGroupingDigits>
+		<symbols numberSystem="latn">
+			<decimal>↑↑↑</decimal>
+			<group>↑↑↑</group>
+			<percentSign>↑↑↑</percentSign>
+			<plusSign>↑↑↑</plusSign>
+			<minusSign>↑↑↑</minusSign>
+			<approximatelySign>↑↑↑</approximatelySign>
+			<exponential>↑↑↑</exponential>
+			<superscriptingExponent>↑↑↑</superscriptingExponent>
+			<perMille>↑↑↑</perMille>
+			<infinity>↑↑↑</infinity>
+			<nan>↑↑↑</nan>
+			<timeSeparator draft="contributed">↑↑↑</timeSeparator>
+		</symbols>
+		<decimalFormats numberSystem="latn">
+			<decimalFormatLength>
+				<decimalFormat>
+					<pattern>#,##,##0.###</pattern>
+				</decimalFormat>
+			</decimalFormatLength>
+			<decimalFormatLength type="long">
+				<decimalFormat>
+					<pattern type="1000" count="one">↑↑↑</pattern>
+					<pattern type="1000" count="other">↑↑↑</pattern>
+					<pattern type="10000" count="one">↑↑↑</pattern>
+					<pattern type="10000" count="other">↑↑↑</pattern>
+					<pattern type="100000" count="one">↑↑↑</pattern>
+					<pattern type="100000" count="other">↑↑↑</pattern>
+					<pattern type="1000000" count="one">↑↑↑</pattern>
+					<pattern type="1000000" count="other">↑↑↑</pattern>
+					<pattern type="10000000" count="one">↑↑↑</pattern>
+					<pattern type="10000000" count="other">↑↑↑</pattern>
+					<pattern type="100000000" count="one">↑↑↑</pattern>
+					<pattern type="100000000" count="other">↑↑↑</pattern>
+					<pattern type="1000000000" count="one">↑↑↑</pattern>
+					<pattern type="1000000000" count="other">↑↑↑</pattern>
+					<pattern type="10000000000" count="one">↑↑↑</pattern>
+					<pattern type="10000000000" count="other">↑↑↑</pattern>
+					<pattern type="100000000000" count="one">↑↑↑</pattern>
+					<pattern type="100000000000" count="other">↑↑↑</pattern>
+					<pattern type="1000000000000" count="one">↑↑↑</pattern>
+					<pattern type="1000000000000" count="other">↑↑↑</pattern>
+					<pattern type="10000000000000" count="one">↑↑↑</pattern>
+					<pattern type="10000000000000" count="other">↑↑↑</pattern>
+					<pattern type="100000000000000" count="one">↑↑↑</pattern>
+					<pattern type="100000000000000" count="other">↑↑↑</pattern>
+				</decimalFormat>
+			</decimalFormatLength>
+			<decimalFormatLength type="short">
+				<decimalFormat>
+					<pattern type="1000" count="one">↑↑↑</pattern>
+					<pattern type="1000" count="other">↑↑↑</pattern>
+					<pattern type="10000" count="one">↑↑↑</pattern>
+					<pattern type="10000" count="other">↑↑↑</pattern>
+					<pattern type="100000" count="one">0L</pattern>
+					<pattern type="100000" count="other">0L</pattern>
+					<pattern type="1000000" count="one">00L</pattern>
+					<pattern type="1000000" count="other">00L</pattern>
+					<pattern type="10000000" count="one">0Cr</pattern>
+					<pattern type="10000000" count="other">0Cr</pattern>
+					<pattern type="100000000" count="one">00Cr</pattern>
+					<pattern type="100000000" count="other">00Cr</pattern>
+					<pattern type="1000000000" count="one">000Cr</pattern>
+					<pattern type="1000000000" count="other">000Cr</pattern>
+					<pattern type="10000000000" count="one">0KCr</pattern>
+					<pattern type="10000000000" count="other">0KCr</pattern>
+					<pattern type="100000000000" count="one">00KCr</pattern>
+					<pattern type="100000000000" count="other">00KCr</pattern>
+					<pattern type="1000000000000" count="one">0LCr</pattern>
+					<pattern type="1000000000000" count="other">0LCr</pattern>
+					<pattern type="10000000000000" count="one">00LCr</pattern>
+					<pattern type="10000000000000" count="other">00LCr</pattern>
+					<pattern type="100000000000000" count="one">000LCr</pattern>
+					<pattern type="100000000000000" count="other">000LCr</pattern>
+				</decimalFormat>
+			</decimalFormatLength>
+		</decimalFormats>
+		<scientificFormats numberSystem="latn">
+			<scientificFormatLength>
+				<scientificFormat>
+					<pattern>↑↑↑</pattern>
+				</scientificFormat>
+			</scientificFormatLength>
+		</scientificFormats>
+		<percentFormats numberSystem="latn">
+			<percentFormatLength>
+				<percentFormat>
+					<pattern>#,##,##0%</pattern>
+				</percentFormat>
+			</percentFormatLength>
+		</percentFormats>
+		<currencyFormats numberSystem="latn">
+			<currencyFormatLength>
+				<currencyFormat type="standard">
+					<pattern>¤#,##,##0.00</pattern>
+					<pattern alt="alphaNextToNumber" draft="provisional">¤ #,##,##0.00</pattern>
+					<pattern alt="noCurrency" draft="provisional">#,##,##0.00</pattern>
+				</currencyFormat>
+				<currencyFormat type="accounting">
+					<pattern>↑↑↑</pattern>
+					<pattern alt="alphaNextToNumber">↑↑↑</pattern>
+					<pattern alt="noCurrency">↑↑↑</pattern>
+				</currencyFormat>
+			</currencyFormatLength>
+			<currencyFormatLength type="short">
+				<currencyFormat type="standard">
+					<pattern type="1000" count="one">↑↑↑</pattern>
+					<pattern type="1000" count="one" alt="alphaNextToNumber">↑↑↑</pattern>
+					<pattern type="1000" count="other">↑↑↑</pattern>
+					<pattern type="1000" count="other" alt="alphaNextToNumber">↑↑↑</pattern>
+					<pattern type="10000" count="one">↑↑↑</pattern>
+					<pattern type="10000" count="one" alt="alphaNextToNumber">↑↑↑</pattern>
+					<pattern type="10000" count="other">↑↑↑</pattern>
+					<pattern type="10000" count="other" alt="alphaNextToNumber">↑↑↑</pattern>
+					<pattern type="100000" count="one">¤0L</pattern>
+					<pattern type="100000" count="one" alt="alphaNextToNumber">¤ 0L</pattern>
+					<pattern type="100000" count="other">¤0L</pattern>
+					<pattern type="100000" count="other" alt="alphaNextToNumber">¤ 0L</pattern>
+					<pattern type="1000000" count="one">¤00L</pattern>
+					<pattern type="1000000" count="one" alt="alphaNextToNumber">¤ 00L</pattern>
+					<pattern type="1000000" count="other">¤00L</pattern>
+					<pattern type="1000000" count="other" alt="alphaNextToNumber">¤ 00L</pattern>
+					<pattern type="10000000" count="one">¤0Cr</pattern>
+					<pattern type="10000000" count="one" alt="alphaNextToNumber">¤ 0Cr</pattern>
+					<pattern type="10000000" count="other">¤0Cr</pattern>
+					<pattern type="10000000" count="other" alt="alphaNextToNumber">¤ 0Cr</pattern>
+					<pattern type="100000000" count="one">¤00Cr</pattern>
+					<pattern type="100000000" count="one" alt="alphaNextToNumber">¤ 00Cr</pattern>
+					<pattern type="100000000" count="other">¤00Cr</pattern>
+					<pattern type="100000000" count="other" alt="alphaNextToNumber">¤ 00Cr</pattern>
+					<pattern type="1000000000" count="one">¤000Cr</pattern>
+					<pattern type="1000000000" count="one" alt="alphaNextToNumber">¤ 000Cr</pattern>
+					<pattern type="1000000000" count="other">¤000Cr</pattern>
+					<pattern type="1000000000" count="other" alt="alphaNextToNumber">¤ 000Cr</pattern>
+					<pattern type="10000000000" count="one">¤0KCr</pattern>
+					<pattern type="10000000000" count="one" alt="alphaNextToNumber">¤ 0KCr</pattern>
+					<pattern type="10000000000" count="other">¤0KCr</pattern>
+					<pattern type="10000000000" count="other" alt="alphaNextToNumber">¤ 0KCr</pattern>
+					<pattern type="100000000000" count="one">¤00KCr</pattern>
+					<pattern type="100000000000" count="one" alt="alphaNextToNumber">¤ 00KCr</pattern>
+					<pattern type="100000000000" count="other">¤00KCr</pattern>
+					<pattern type="100000000000" count="other" alt="alphaNextToNumber">¤ 00KCr</pattern>
+					<pattern type="1000000000000" count="one">¤0LCr</pattern>
+					<pattern type="1000000000000" count="one" alt="alphaNextToNumber">¤ 0LCr</pattern>
+					<pattern type="1000000000000" count="other">¤0LCr</pattern>
+					<pattern type="1000000000000" count="other" alt="alphaNextToNumber">¤ 0LCr</pattern>
+					<pattern type="10000000000000" count="one">¤00LCr</pattern>
+					<pattern type="10000000000000" count="one" alt="alphaNextToNumber">¤ 00LCr</pattern>
+					<pattern type="10000000000000" count="other">¤00LCr</pattern>
+					<pattern type="10000000000000" count="other" alt="alphaNextToNumber">¤ 00LCr</pattern>
+					<pattern type="100000000000000" count="one">¤000LCr</pattern>
+					<pattern type="100000000000000" count="one" alt="alphaNextToNumber">¤ 000LCr</pattern>
+					<pattern type="100000000000000" count="other">¤000LCr</pattern>
+					<pattern type="100000000000000" count="other" alt="alphaNextToNumber">¤ 000LCr</pattern>
+				</currencyFormat>
+			</currencyFormatLength>
+			<currencyPatternAppendISO>↑↑↑</currencyPatternAppendISO>
+			<unitPattern count="one">↑↑↑</unitPattern>
+			<unitPattern count="other">↑↑↑</unitPattern>
+		</currencyFormats>
+	</numbers>
+</ldml>
diff --git a/common/main/en_CO.xml b/common/main/en_CO.xml
new file mode 100644
index 00000000..98eb79fe
--- /dev/null
+++ b/common/main/en_CO.xml
@@ -0,0 +1,35 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="CO"/>
+	</identity>
+	<numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group>.</group>
+		</symbols>
+		<currencyFormats numberSystem="latn">
+			<currencyFormatLength>
+				<currencyFormat type="standard">
+					<pattern draft="contributed">¤ #,##0.00</pattern>
+				</currencyFormat>
+			</currencyFormatLength>
+		</currencyFormats>
+		<currencies>
+			<currency type="COP">
+				<symbol>$</symbol>
+			</currency>
+			<currency type="USD">
+				<symbol>US$</symbol>
+			</currency>
+		</currencies>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_EE.xml b/common/main/en_EE.xml
new file mode 100644
index 00000000..aea5460b
--- /dev/null
+++ b/common/main/en_EE.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="EE"/>
+	</identity>
+	<numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group> </group>
+		</symbols>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_GE.xml b/common/main/en_GE.xml
new file mode 100644
index 00000000..8f893255
--- /dev/null
+++ b/common/main/en_GE.xml
@@ -0,0 +1,32 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="GE"/>
+	</identity>
+	<numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group> </group>
+		</symbols>
+		<currencyFormats numberSystem="latn">
+			<currencyFormatLength>
+				<currencyFormat type="standard">
+					<pattern>#,##0.00 ¤</pattern>
+				</currencyFormat>
+			</currencyFormatLength>
+		</currencyFormats>
+		<currencies>
+			<currency type="GEL">
+				<symbol>₾</symbol>
+			</currency>
+		</currencies>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_JP.xml b/common/main/en_JP.xml
new file mode 100644
index 00000000..a4e1c623
--- /dev/null
+++ b/common/main/en_JP.xml
@@ -0,0 +1,804 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="JP"/>
+	</identity>
+	<dates>
+		<calendars>
+			<calendar type="generic">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>GGGGG y/MM/dd</pattern>
+							<datetimeSkeleton>GGGGGyMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Bh">h B</dateFormatItem>
+						<dateFormatItem id="Bhm">h:mm B</dateFormatItem>
+						<dateFormatItem id="Bhms">h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="EBhm">E h:mm B</dateFormatItem>
+						<dateFormatItem id="EBhms">E h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Ehm">E h:mm a</dateFormatItem>
+						<dateFormatItem id="Ehm" alt="ascii">E h:mm a</dateFormatItem>
+						<dateFormatItem id="EHm">E H:mm</dateFormatItem>
+						<dateFormatItem id="Ehms">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Ehms" alt="ascii">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="EHms">E H:mm:ss</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">GGGGG y/MM/dd</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="h" alt="ascii">h a</dateFormatItem>
+						<dateFormatItem id="H">H</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="hm" alt="ascii">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">H:mm</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="hms" alt="ascii">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">H:mm:ss</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">MM/dd</dateFormatItem>
+						<dateFormatItem id="MEd">E, MM/dd</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="ms">mm:ss</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">GGGGG y/MM</dateFormatItem>
+						<dateFormatItem id="yyyyMd">GGGGG y/MM/dd</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">GGGGG y/MM/dd, E</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>{0} – {1}</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d – d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="G">G y – G y</greatestDifference>
+							<greatestDifference id="y">G y – y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyM">
+							<greatestDifference id="G">GGGGG y/MM – GGGGG y/MM</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM – y/MM</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM – y/MM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="G">GGGGG y/MM/dd – GGGGG y/MM/dd</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">GGGGG y/MM/dd, E – E, y/MM/dd, E</greatestDifference>
+							<greatestDifference id="G">GGGGG y/MM/dd, E  – GGGGG y/MM/dd, E</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd, E – E, y/MM/dd, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMM">
+							<greatestDifference id="G">MMM y G – MMM y G</greatestDifference>
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="G">MMM d, y G – MMM d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="G">E, MMM d, y G – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">H – H</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">H:mm – H:mm</greatestDifference>
+							<greatestDifference id="m">H:mm – H:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">H:mm – H:mm v</greatestDifference>
+							<greatestDifference id="m">H:mm – H:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">H – H v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M – M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">MM/dd – MM/dd</greatestDifference>
+							<greatestDifference id="M">MM/dd – MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E, MM/dd – E, MM/dd</greatestDifference>
+							<greatestDifference id="M">E, MM/dd – E, MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">MMM d – d</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">GGGGG y/MM – y/MM</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM – yMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M">MMMM – MMMM y G</greatestDifference>
+							<greatestDifference id="y">MMMM y – MMMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="gregorian">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y</pattern>
+							<datetimeSkeleton>yMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y</pattern>
+							<datetimeSkeleton>yMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y</pattern>
+							<datetimeSkeleton>yMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>y/MM/dd</pattern>
+							<datetimeSkeleton>yMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<timeFormats>
+					<timeFormatLength type="full">
+						<timeFormat>
+							<pattern>H:mm:ss zzzz</pattern>
+							<datetimeSkeleton>Hmmsszzzz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="long">
+						<timeFormat>
+							<pattern>H:mm:ss z</pattern>
+							<datetimeSkeleton>Hmmssz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="medium">
+						<timeFormat>
+							<pattern>H:mm:ss</pattern>
+							<datetimeSkeleton>Hmmss</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="short">
+						<timeFormat>
+							<pattern>H:mm</pattern>
+							<datetimeSkeleton>Hmm</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+				</timeFormats>
+				<dateTimeFormats>
+					<dateTimeFormatLength type="full">
+						<dateTimeFormat>
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1} 'at' {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<dateTimeFormatLength type="long">
+						<dateTimeFormat>
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1} 'at' {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<dateTimeFormatLength type="medium">
+						<dateTimeFormat>
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<dateTimeFormatLength type="short">
+						<dateTimeFormat>
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+						<dateTimeFormat type="atTime">
+							<pattern>{1}, {0}</pattern>
+						</dateTimeFormat>
+					</dateTimeFormatLength>
+					<availableFormats>
+						<dateFormatItem id="Bh">h B</dateFormatItem>
+						<dateFormatItem id="Bhm">h:mm B</dateFormatItem>
+						<dateFormatItem id="Bhms">h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="EBhm">E h:mm B</dateFormatItem>
+						<dateFormatItem id="EBhms">E h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Ehm">E h:mm a</dateFormatItem>
+						<dateFormatItem id="Ehm" alt="ascii">E h:mm a</dateFormatItem>
+						<dateFormatItem id="EHm">E HH:mm</dateFormatItem>
+						<dateFormatItem id="Ehms">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Ehms" alt="ascii">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="EHms">E HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">y/MM/dd G</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="h" alt="ascii">h a</dateFormatItem>
+						<dateFormatItem id="H">H</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="hm" alt="ascii">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">H:mm</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="hms" alt="ascii">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">H:mm:ss</dateFormatItem>
+						<dateFormatItem id="hmsv">h:mm:ss a v</dateFormatItem>
+						<dateFormatItem id="hmsv" alt="ascii">h:mm:ss a v</dateFormatItem>
+						<dateFormatItem id="Hmsv">H:mm:ss v</dateFormatItem>
+						<dateFormatItem id="hmv">h:mm a v</dateFormatItem>
+						<dateFormatItem id="hmv" alt="ascii">h:mm a v</dateFormatItem>
+						<dateFormatItem id="Hmv">H:mm v</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">MM/dd</dateFormatItem>
+						<dateFormatItem id="MEd">E, MM/dd</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="MMMMW" count="one">'week' W 'of' MMMM</dateFormatItem>
+						<dateFormatItem id="MMMMW" count="other">'week' W 'of' MMMM</dateFormatItem>
+						<dateFormatItem id="ms">mm:ss</dateFormatItem>
+						<dateFormatItem id="y">y</dateFormatItem>
+						<dateFormatItem id="yM">y/MM</dateFormatItem>
+						<dateFormatItem id="yMd">y/MM/dd</dateFormatItem>
+						<dateFormatItem id="yMEd">E, y/MM/dd</dateFormatItem>
+						<dateFormatItem id="yMMM">MMM y</dateFormatItem>
+						<dateFormatItem id="yMMMd">MMM d, y</dateFormatItem>
+						<dateFormatItem id="yMMMEd">E, MMM d, y</dateFormatItem>
+						<dateFormatItem id="yMMMM">MMMM y</dateFormatItem>
+						<dateFormatItem id="yQQQ">QQQ y</dateFormatItem>
+						<dateFormatItem id="yQQQQ">QQQQ y</dateFormatItem>
+						<dateFormatItem id="yw" count="one">'week' w 'of' Y</dateFormatItem>
+						<dateFormatItem id="yw" count="other">'week' w 'of' Y</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>{0} – {1}</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d – d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="G">y G – y G</greatestDifference>
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyM">
+							<greatestDifference id="G">MM/y G – MM/y G</greatestDifference>
+							<greatestDifference id="M">MM/y – MM/y G</greatestDifference>
+							<greatestDifference id="y">MM/y – MM/y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">y/MM/dd – y/MM/dd G</greatestDifference>
+							<greatestDifference id="G">y/MM/dd G – y/MM/dd G</greatestDifference>
+							<greatestDifference id="M">y/MM/dd – y/MM/dd G</greatestDifference>
+							<greatestDifference id="y">y/MM/dd – y/MM/dd G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, y/MM/dd – E, y/MM/dd G</greatestDifference>
+							<greatestDifference id="G">E, y/MM/dd G – E, y/MM/dd G</greatestDifference>
+							<greatestDifference id="M">E, y/MM/dd – E, y/MM/dd G</greatestDifference>
+							<greatestDifference id="y">E, y/MM/dd – E, y/MM/dd G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMM">
+							<greatestDifference id="G">MMM y G – MMM y G</greatestDifference>
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="G">MMM d, y G – MMM d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="G">E, MMM d, y G – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">HH – HH</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">HH:mm – HH:mm</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">HH:mm – HH:mm v</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">HH – HH v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M – M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">M/d – M/d</greatestDifference>
+							<greatestDifference id="M">M/d – M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E, M/d – E, M/d</greatestDifference>
+							<greatestDifference id="M">E, M/d – E, M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">MMM d – d</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y – y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">MM/y – MM/y</greatestDifference>
+							<greatestDifference id="y">MM/y – MM/y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="M">y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="y">y/MM/dd – y/MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, y/MM/dd – E, y/MM/dd</greatestDifference>
+							<greatestDifference id="M">E, y/MM/dd – E, y/MM/dd</greatestDifference>
+							<greatestDifference id="y">E, y/MM/dd – E, y/MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M">MMM – MMM y</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">MMM d – d, y</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M">MMMM – MMMM y</greatestDifference>
+							<greatestDifference id="y">MMMM y – MMMM y</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="japanese">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>GGGGG y/MM/dd</pattern>
+							<datetimeSkeleton>GGGGGyMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="d">↑↑↑</dateFormatItem>
+						<dateFormatItem id="E">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ed">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EEEEd">EEEE d</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">↑↑↑</dateFormatItem>
+						<dateFormatItem id="GyMMM">↑↑↑</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEEEEd">EEEE, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">↑↑↑</dateFormatItem>
+						<dateFormatItem id="H">↑↑↑</dateFormatItem>
+						<dateFormatItem id="hm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Hm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="hms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Hms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="M">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Md">↑↑↑</dateFormatItem>
+						<dateFormatItem id="MEd">↑↑↑</dateFormatItem>
+						<dateFormatItem id="MEEEEd">EEEE, MM/dd</dateFormatItem>
+						<dateFormatItem id="MMM">↑↑↑</dateFormatItem>
+						<dateFormatItem id="MMMd">↑↑↑</dateFormatItem>
+						<dateFormatItem id="MMMEd">↑↑↑</dateFormatItem>
+						<dateFormatItem id="MMMEEEEd">EEEE, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">↑↑↑</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">GGGGG y/MM</dateFormatItem>
+						<dateFormatItem id="yyyyMd">GGGGG y/MM/dd</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">GGGGG y/MM/dd EEEE</dateFormatItem>
+						<dateFormatItem id="yyyyMEEEEd">EEEE, MMM d, y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMM">MM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">G y MMM d</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>{0} – {1}</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d – d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="G">G y – G y</greatestDifference>
+							<greatestDifference id="y">G y – y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyM">
+							<greatestDifference id="G">GGGGG y/MM – GGGGG y/MM</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM – y/MM</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM – y/MM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="G">GGGGG y/MM/dd – GGGGG y/MM/dd</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">GGGGG y/MM/dd, E – E, y/MM/dd, E</greatestDifference>
+							<greatestDifference id="G">GGGGG y/MM/dd, E  – GGGGG y/MM/dd, E</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd, E – E, y/MM/dd, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMM">
+							<greatestDifference id="G">MMM y G – MMM y G</greatestDifference>
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="G">MMM d, y G – MMM d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="G">E, MMM d, y G – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">H – H</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">H:mm – H:mm</greatestDifference>
+							<greatestDifference id="m">H:mm – H:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">H:mm – H:mm v</greatestDifference>
+							<greatestDifference id="m">H:mm – H:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">H – H v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M – M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">MM/dd – MM/dd</greatestDifference>
+							<greatestDifference id="M">MM/dd – MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E, MM/dd – E, MM/dd</greatestDifference>
+							<greatestDifference id="M">E, MM/dd – E, MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">MMM d – d</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">GGGGG y/MM – y/MM</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM – yMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd – y/MM/dd</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+							<greatestDifference id="M">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+							<greatestDifference id="y">GGGGG y/MM/dd, E – y/MM/dd, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M">MMMM – MMMM y G</greatestDifference>
+							<greatestDifference id="y">MMMM y – MMMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+		</calendars>
+		<timeZoneNames>
+			<zone type="Pacific/Honolulu">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</zone>
+			<metazone type="Alaska">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Central">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Eastern">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Mountain">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Pacific">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="Atlantic">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="Hawaii_Aleutian">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="Japan">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>JST</standard>
+					<daylight>JDT</daylight>
+				</short>
+			</metazone>
+		</timeZoneNames>
+	</dates>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_KH.xml b/common/main/en_KH.xml
new file mode 100644
index 00000000..3a191ebf
--- /dev/null
+++ b/common/main/en_KH.xml
@@ -0,0 +1,360 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="KH"/>
+	</identity>
+	<dates>
+		<calendars>
+			<calendar type="generic">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, d MMMM y G</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>d MMMM y G</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>d MMM y G</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>d/M/y GGGGG</pattern>
+							<datetimeSkeleton>GGGGGyMMdd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Bhms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EBhm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EBhms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ed">E d</dateFormatItem>
+						<dateFormatItem id="Ehm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ehm" alt="ascii">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EHm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ehms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ehms" alt="ascii">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EHms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="GyMd">d/M/y GGGGG</dateFormatItem>
+						<dateFormatItem id="GyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, d MMM y G</dateFormatItem>
+						<dateFormatItem id="M">LL</dateFormatItem>
+						<dateFormatItem id="Md">d/M</dateFormatItem>
+						<dateFormatItem id="MEd">E, d/M</dateFormatItem>
+						<dateFormatItem id="MMMd">d MMM</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, d MMM</dateFormatItem>
+						<dateFormatItem id="MMMMd">d MMMM</dateFormatItem>
+						<dateFormatItem id="yyyyM">M/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMd">d/M/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">E, d/M/y GGGGG</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, d MMM y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d–d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="y">y–y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">d/M/y – d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="G">d/M/y GGGGG – d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="M">d/M/y – d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">d/M/y – d/M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, d/M/y – E, d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="G">E, d/M/y GGGGG – E, d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, d/M/y – E, d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, d/M/y – E, d/M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">d–d MMM y G</greatestDifference>
+							<greatestDifference id="G">d MMM y G – d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="G">E, d MMM y G – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M–M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">d/M – d/M</greatestDifference>
+							<greatestDifference id="M">d/M – d/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E d/M – E d/M</greatestDifference>
+							<greatestDifference id="M">E d/M – E d/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">d–d MMM</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E d – E d MMM</greatestDifference>
+							<greatestDifference id="M">E d MMM – E d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y–y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">M/y – M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">M/y – M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">d/M/y – d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="M">d/M/y – d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">d/M/y – d/M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, d/M/y – E, d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="M">E, d/M/y – E, d/M/y GGGGG</greatestDifference>
+							<greatestDifference id="y">E, d/M/y – E, d/M/y GGGGG</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">d–d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, d – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="gregorian">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, d MMMM y</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>d MMMM y</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>d MMM y</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>d/M/y</pattern>
+							<datetimeSkeleton>yMMdd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="EBhm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EBhms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ed">E d</dateFormatItem>
+						<dateFormatItem id="Ehm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ehm" alt="ascii">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EHm">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ehms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="Ehms" alt="ascii">↑↑↑</dateFormatItem>
+						<dateFormatItem id="EHms">↑↑↑</dateFormatItem>
+						<dateFormatItem id="GyMd">d/M/y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">d MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, d MMM y G</dateFormatItem>
+						<dateFormatItem id="Md">d/M</dateFormatItem>
+						<dateFormatItem id="MEd">E, d/M</dateFormatItem>
+						<dateFormatItem id="MMdd">d/M</dateFormatItem>
+						<dateFormatItem id="MMMd">d MMM</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, d MMM</dateFormatItem>
+						<dateFormatItem id="MMMMd">d MMMM</dateFormatItem>
+						<dateFormatItem id="yM">M/y</dateFormatItem>
+						<dateFormatItem id="yMd">d/M/y</dateFormatItem>
+						<dateFormatItem id="yMEd">E, d/M/y</dateFormatItem>
+						<dateFormatItem id="yMMMd">d MMM y</dateFormatItem>
+						<dateFormatItem id="yMMMEd">E, d MMM y</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d–d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">d/M/y – d/M/y G</greatestDifference>
+							<greatestDifference id="G">d/M/y G – d/M/y G</greatestDifference>
+							<greatestDifference id="M">d/M/y – d/M/y G</greatestDifference>
+							<greatestDifference id="y">d/M/y – d/M/y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">E, d/M/y – E, d/M/y G</greatestDifference>
+							<greatestDifference id="G">E, d/M/y G – E, d/M/y G</greatestDifference>
+							<greatestDifference id="M">E, d/M/y – E, d/M/y G</greatestDifference>
+							<greatestDifference id="y">E, d/M/y – E, d/M/y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">d – d MMM y G</greatestDifference>
+							<greatestDifference id="G">d MMM y G – d MMM y G</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y G</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="G">E, d MMM y G – E, d MMM y G</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y G</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="h">h–h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">HH–HH</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">HH:mm–HH:mm</greatestDifference>
+							<greatestDifference id="m">HH:mm–HH:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">HH:mm–HH:mm v</greatestDifference>
+							<greatestDifference id="m">HH:mm–HH:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="h">h–h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">HH–HH v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M–M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">d/M – d/M</greatestDifference>
+							<greatestDifference id="M">d/M – d/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E d/M – E d/M</greatestDifference>
+							<greatestDifference id="M">E d/M – E d/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">d–d MMM</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E d – E d MMM</greatestDifference>
+							<greatestDifference id="M">E d MMM – E d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">y–y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">M/y – M/y</greatestDifference>
+							<greatestDifference id="y">M/y – M/y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">d/M/y – d/M/y</greatestDifference>
+							<greatestDifference id="M">d/M/y – d/M/y</greatestDifference>
+							<greatestDifference id="y">d/M/y – d/M/y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, d/M/y – E, d/M/y</greatestDifference>
+							<greatestDifference id="M">E, d/M/y – E, d/M/y</greatestDifference>
+							<greatestDifference id="y">E, d/M/y – E, d/M/y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">d–d MMM y</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM y</greatestDifference>
+							<greatestDifference id="y">d MMM y – d MMM y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, d – E, d MMM y</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM y</greatestDifference>
+							<greatestDifference id="y">E, d MMM y – E, d MMM y</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+		</calendars>
+		<timeZoneNames>
+			<zone type="Pacific/Honolulu">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</zone>
+			<metazone type="Alaska">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Central">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Eastern">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Mountain">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="America_Pacific">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="Atlantic">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+			<metazone type="Hawaii_Aleutian">
+				<short>
+					<generic>∅∅∅</generic>
+					<standard>∅∅∅</standard>
+					<daylight>∅∅∅</daylight>
+				</short>
+			</metazone>
+		</timeZoneNames>
+	</dates>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_LK.xml b/common/main/en_LK.xml
new file mode 100644
index 00000000..34c290d5
--- /dev/null
+++ b/common/main/en_LK.xml
@@ -0,0 +1,46 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2024 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="LK"/>
+	</identity>
+	<dates>
+		<calendars>
+			<calendar type="gregorian">
+				<timeFormats>
+					<timeFormatLength type="full">
+						<timeFormat>
+							<pattern>HH:mm:ss zzzz</pattern>
+							<datetimeSkeleton>HHmmsszzzz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="long">
+						<timeFormat>
+							<pattern>HH:mm:ss z</pattern>
+							<datetimeSkeleton>HHmmssz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="medium">
+						<timeFormat>
+							<pattern>HH:mm:ss</pattern>
+							<datetimeSkeleton>HHmmss</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="short">
+						<timeFormat>
+							<pattern>HH:mm</pattern>
+							<datetimeSkeleton>HHmm</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+				</timeFormats>
+			</calendar>
+		</calendars>
+	</dates>
+</ldml>
diff --git a/common/main/en_LT.xml b/common/main/en_LT.xml
new file mode 100644
index 00000000..54b25dba
--- /dev/null
+++ b/common/main/en_LT.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="LT"/>
+	</identity>
+	<numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group> </group>
+		</symbols>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_LV.xml b/common/main/en_LV.xml
new file mode 100644
index 00000000..20e7d209
--- /dev/null
+++ b/common/main/en_LV.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="LV"/>
+	</identity>
+	<numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group> </group>
+		</symbols>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_MA.xml b/common/main/en_MA.xml
new file mode 100644
index 00000000..53212d9f
--- /dev/null
+++ b/common/main/en_MA.xml
@@ -0,0 +1,46 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="MA"/>
+	</identity>
+	<dates>
+		<calendars>
+			<calendar type="gregorian">
+				<timeFormats>
+					<timeFormatLength type="full">
+						<timeFormat>
+							<pattern>HH:mm:ss zzzz</pattern>
+							<datetimeSkeleton>HHmmsszzzz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="long">
+						<timeFormat>
+							<pattern>HH:mm:ss z</pattern>
+							<datetimeSkeleton>HHmmssz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="medium">
+						<timeFormat>
+							<pattern>HH:mm:ss</pattern>
+							<datetimeSkeleton>HHmmss</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="short">
+						<timeFormat>
+							<pattern>HH:mm</pattern>
+							<datetimeSkeleton>HHmm</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+				</timeFormats>
+			</calendar>
+		</calendars>
+	</dates>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_MX.xml b/common/main/en_MX.xml
new file mode 100644
index 00000000..90849d6f
--- /dev/null
+++ b/common/main/en_MX.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="MX"/>
+	</identity>
+	<numbers>
+		<currencies>
+			<currency type="MXN">
+				<symbol>$</symbol>
+			</currency>
+			<currency type="USD">
+				<symbol>US$</symbol>
+			</currency>
+		</currencies>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_SA.xml b/common/main/en_SA.xml
new file mode 100644
index 00000000..1b55ff2c
--- /dev/null
+++ b/common/main/en_SA.xml
@@ -0,0 +1,14 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="SA"/>
+	</identity>
+</ldml>
diff --git a/common/main/en_TW.xml b/common/main/en_TW.xml
new file mode 100644
index 00000000..c66dbe31
--- /dev/null
+++ b/common/main/en_TW.xml
@@ -0,0 +1,716 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="TW"/>
+	</identity>
+	<dates>
+		<calendars>
+    			<calendar type="chinese">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, d MMMM r(U)</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>d MMMM r(U)</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>d MMM r</pattern>
+							<datetimeSkeleton>↑↑↑</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>r/M/d</pattern>
+							<datetimeSkeleton>rMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Ed">E d</dateFormatItem>
+						<dateFormatItem id="GyMMMd">d MMM r</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, d MMM r</dateFormatItem>
+						<dateFormatItem id="GyMMMMd">d MMMM r(U)</dateFormatItem>
+						<dateFormatItem id="GyMMMMEd">E, d MMMM r(U)</dateFormatItem>
+						<dateFormatItem id="M">LL</dateFormatItem>
+						<dateFormatItem id="Md">M/d</dateFormatItem>
+						<dateFormatItem id="MEd">E, M/d</dateFormatItem>
+						<dateFormatItem id="MMMd">d MMM</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, d MMM</dateFormatItem>
+						<dateFormatItem id="MMMMd">d MMMM</dateFormatItem>
+						<dateFormatItem id="UMd">U/M/d</dateFormatItem>
+						<dateFormatItem id="UMMMd">d MMM U</dateFormatItem>
+						<dateFormatItem id="yyyyM">r/M</dateFormatItem>
+						<dateFormatItem id="yyyyMd">r/M/d</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">E, r/M/d</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">d MMM r</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, d MMM r</dateFormatItem>
+						<dateFormatItem id="yyyyMMMMd">d MMMM r(U)</dateFormatItem>
+						<dateFormatItem id="yyyyMMMMEd">E, d MMMM r(U)</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">M/d – M/d</greatestDifference>
+							<greatestDifference id="M">M/d – M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">M/d, E – M/d, E</greatestDifference>
+							<greatestDifference id="M">M/d, E – M/d, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">d – d MMM</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E d – E d MMM</greatestDifference>
+							<greatestDifference id="M">E d MMM – E d MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">y/M – y/M</greatestDifference>
+							<greatestDifference id="y">y/M – y/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">y/M/d – y/M/d</greatestDifference>
+							<greatestDifference id="M">y/M/d – y/M/d</greatestDifference>
+							<greatestDifference id="y">y/M/d – y/M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">E, y/M/d – E, y/M/d</greatestDifference>
+							<greatestDifference id="M">E, y/M/d – E, y/M/d</greatestDifference>
+							<greatestDifference id="y">E, y/M/d – E, y/M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">d – d MMM U</greatestDifference>
+							<greatestDifference id="M">d MMM – d MMM U</greatestDifference>
+							<greatestDifference id="y">d MMM U – d MMM U</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, d – E, d MMM U</greatestDifference>
+							<greatestDifference id="M">E, d MMM – E, d MMM U</greatestDifference>
+							<greatestDifference id="y">E, d MMM U – E, d MMM U</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="generic">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>GGGGG y/M/d</pattern>
+							<datetimeSkeleton>GGGGGyMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Bh">h B</dateFormatItem>
+						<dateFormatItem id="Bhm">h:mm B</dateFormatItem>
+						<dateFormatItem id="Bhms">h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="EBhm">E h:mm B</dateFormatItem>
+						<dateFormatItem id="EBhms">E h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Ehm">E h:mm a</dateFormatItem>
+						<dateFormatItem id="Ehm" alt="ascii">E h:mm a</dateFormatItem>
+						<dateFormatItem id="EHm">E HH:mm</dateFormatItem>
+						<dateFormatItem id="Ehms">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Ehms" alt="ascii">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="EHms">E HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">G y/M/d</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="h" alt="ascii">h a</dateFormatItem>
+						<dateFormatItem id="H">HH</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">HH:mm</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">M/d</dateFormatItem>
+						<dateFormatItem id="MEd">E, M/d</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="ms">mm:ss</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">G y/M</dateFormatItem>
+						<dateFormatItem id="yyyyMd">G y/M/d</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">G y/M/d, E</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>{0} – {1}</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d">d – d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Gy">
+							<greatestDifference id="G">y G – y G</greatestDifference>
+							<greatestDifference id="y">y – y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyM">
+							<greatestDifference id="G">G y/M – G y/M</greatestDifference>
+							<greatestDifference id="M">G y/M – y/M</greatestDifference>
+							<greatestDifference id="y">G y/M – y/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMd">
+							<greatestDifference id="d">G y/M/d – y/M/d</greatestDifference>
+							<greatestDifference id="G">G y/M/d – G y/M/d</greatestDifference>
+							<greatestDifference id="M">G y/M/d – y/M/d</greatestDifference>
+							<greatestDifference id="y">G y/M/d – y/M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMEd">
+							<greatestDifference id="d">G y/M/d, E – y/M/d, E</greatestDifference>
+							<greatestDifference id="G">G y/M/d, E – G y/M/d, E</greatestDifference>
+							<greatestDifference id="M">G y/M/d, E – y/M/d, E</greatestDifference>
+							<greatestDifference id="y">G y/M/d, E – y/M/d, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMM">
+							<greatestDifference id="G">MMM y G – MMM y G</greatestDifference>
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="G">MMM d, y G – MMM d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="GyMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="G">E, MMM d, y G – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H">HH – HH</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H">HH:mm – HH:mm</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">HH:mm – HH:mm v</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">HH – HH v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M">M – M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d">M/d – M/d</greatestDifference>
+							<greatestDifference id="M">M/d – M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d">E, M/d – E, M/d</greatestDifference>
+							<greatestDifference id="M">E, M/d – E, M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d">MMM d – d</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y">G y – y</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M">G y/M – y/M</greatestDifference>
+							<greatestDifference id="y">G y/M – y/M</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d">G y/M/d – y/M/d</greatestDifference>
+							<greatestDifference id="M">G y/M/d – y/M/d</greatestDifference>
+							<greatestDifference id="y">G y/M/d – y/M/d</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d">G y/M/d, E – y/M/d, E</greatestDifference>
+							<greatestDifference id="M">G y/M/d, E – y/M/d, E</greatestDifference>
+							<greatestDifference id="y">G y/M/d, E – y/M/d, E</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M">MMM – MMM y G</greatestDifference>
+							<greatestDifference id="y">MMM y – MMM y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d">MMM d – d, y G</greatestDifference>
+							<greatestDifference id="M">MMM d – MMM d, y G</greatestDifference>
+							<greatestDifference id="y">MMM d, y – MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="M">E, MMM d – E, MMM d, y G</greatestDifference>
+							<greatestDifference id="y">E, MMM d, y – E, MMM d, y G</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M">MMMM – MMMM y G</greatestDifference>
+							<greatestDifference id="y">MMMM y – MMMM y G</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="gregorian">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y</pattern>
+							<datetimeSkeleton>yMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y</pattern>
+							<datetimeSkeleton>yMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y</pattern>
+							<datetimeSkeleton>yMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>y/M/d</pattern>
+							<datetimeSkeleton>yMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<timeFormats>
+					<timeFormatLength type="full">
+						<timeFormat>
+							<pattern>h:mm:ss a zzzz</pattern>
+							<pattern alt="ascii">h:mm:ss a zzzz</pattern>
+							<datetimeSkeleton>ahmmsszzzz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="long">
+						<timeFormat>
+							<pattern>h:mm:ss a z</pattern>
+							<pattern alt="ascii">h:mm:ss a z</pattern>
+							<datetimeSkeleton>ahmmssz</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="medium">
+						<timeFormat>
+							<pattern>h:mm:ss a</pattern>
+							<pattern alt="ascii">h:mm:ss a</pattern>
+							<datetimeSkeleton>ahmmss</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+					<timeFormatLength type="short">
+						<timeFormat>
+							<pattern>h:mm a</pattern>
+							<pattern alt="ascii">h:mm a</pattern>
+							<datetimeSkeleton>ahmm</datetimeSkeleton>
+						</timeFormat>
+					</timeFormatLength>
+				</timeFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Bh">h B</dateFormatItem>
+						<dateFormatItem id="Bhm">h:mm B</dateFormatItem>
+						<dateFormatItem id="Bhms">h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="EBhm">E h:mm B</dateFormatItem>
+						<dateFormatItem id="EBhms">E h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Ehm">E h:mm a</dateFormatItem>
+						<dateFormatItem id="Ehm" alt="ascii">E h:mm a</dateFormatItem>
+						<dateFormatItem id="EHm">E HH:mm</dateFormatItem>
+						<dateFormatItem id="Ehms">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Ehms" alt="ascii">E h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="EHms">E HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">G y/M/d</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="h" alt="ascii">h a</dateFormatItem>
+						<dateFormatItem id="H">HH</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="hm" alt="ascii">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">HH:mm</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="hms" alt="ascii">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="hmsv">h:mm:ss a v</dateFormatItem>
+						<dateFormatItem id="hmsv" alt="ascii">h:mm:ss a v</dateFormatItem>
+						<dateFormatItem id="Hmsv">HH:mm:ss v</dateFormatItem>
+						<dateFormatItem id="hmv">h:mm a v</dateFormatItem>
+						<dateFormatItem id="hmv" alt="ascii">h:mm a v</dateFormatItem>
+						<dateFormatItem id="Hmv">HH:mm v</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">M/d</dateFormatItem>
+						<dateFormatItem id="MEd">E, M/d</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="ms">mm:ss</dateFormatItem>
+						<dateFormatItem id="y">y</dateFormatItem>
+						<dateFormatItem id="yM">y/M</dateFormatItem>
+						<dateFormatItem id="yMd">y/M/d</dateFormatItem>
+						<dateFormatItem id="yMEd">E, y/M/d</dateFormatItem>
+						<dateFormatItem id="yMMM">MMM y</dateFormatItem>
+						<dateFormatItem id="yMMMd">MMM d, y</dateFormatItem>
+						<dateFormatItem id="yMMMEd">E, MMM d, y</dateFormatItem>
+						<dateFormatItem id="yMMMM">MMMM y</dateFormatItem>
+						<dateFormatItem id="yQQQ">QQQ y</dateFormatItem>
+						<dateFormatItem id="yQQQQ">QQQQ y</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="h" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="h" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="m" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="a" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="h" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="a" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="h" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="m" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm a v</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H">HH:mm – HH:mm v</greatestDifference>
+							<greatestDifference id="m">HH:mm – HH:mm v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H">HH – HH v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M" draft="contributed">MMM – MMM</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+			<calendar type="roc">
+				<dateFormats>
+					<dateFormatLength type="full">
+						<dateFormat>
+							<pattern>EEEE, MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMEEEEd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="long">
+						<dateFormat>
+							<pattern>MMMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="medium">
+						<dateFormat>
+							<pattern>MMM d, y G</pattern>
+							<datetimeSkeleton>GyMMMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+					<dateFormatLength type="short">
+						<dateFormat>
+							<pattern>G y/M/d</pattern>
+							<datetimeSkeleton>GyMd</datetimeSkeleton>
+						</dateFormat>
+					</dateFormatLength>
+				</dateFormats>
+				<dateTimeFormats>
+					<availableFormats>
+						<dateFormatItem id="Bh">h B</dateFormatItem>
+						<dateFormatItem id="Bhm">h:mm B</dateFormatItem>
+						<dateFormatItem id="Bhms">h:mm:ss B</dateFormatItem>
+						<dateFormatItem id="d">d</dateFormatItem>
+						<dateFormatItem id="E">ccc</dateFormatItem>
+						<dateFormatItem id="Ed">d E</dateFormatItem>
+						<dateFormatItem id="Gy">y G</dateFormatItem>
+						<dateFormatItem id="GyMd">G y/M/d</dateFormatItem>
+						<dateFormatItem id="GyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="GyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="GyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="h">h a</dateFormatItem>
+						<dateFormatItem id="H">HH</dateFormatItem>
+						<dateFormatItem id="hm">h:mm a</dateFormatItem>
+						<dateFormatItem id="Hm">HH:mm</dateFormatItem>
+						<dateFormatItem id="hms">h:mm:ss a</dateFormatItem>
+						<dateFormatItem id="Hms">HH:mm:ss</dateFormatItem>
+						<dateFormatItem id="M">L</dateFormatItem>
+						<dateFormatItem id="Md">M/d</dateFormatItem>
+						<dateFormatItem id="MEd">E, M/d</dateFormatItem>
+						<dateFormatItem id="MMM">LLL</dateFormatItem>
+						<dateFormatItem id="MMMd">MMM d</dateFormatItem>
+						<dateFormatItem id="MMMEd">E, MMM d</dateFormatItem>
+						<dateFormatItem id="MMMMd">MMMM d</dateFormatItem>
+						<dateFormatItem id="y">y G</dateFormatItem>
+						<dateFormatItem id="yyyy">y G</dateFormatItem>
+						<dateFormatItem id="yyyyM">G y/M</dateFormatItem>
+						<dateFormatItem id="yyyyMd">G y/M/d</dateFormatItem>
+						<dateFormatItem id="yyyyMEd">G y/M/d, E</dateFormatItem>
+						<dateFormatItem id="yyyyMMM">MMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMd">MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMEd">E, MMM d, y G</dateFormatItem>
+						<dateFormatItem id="yyyyMMMM">MMMM y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQ">QQQ y G</dateFormatItem>
+						<dateFormatItem id="yyyyQQQQ">QQQQ y G</dateFormatItem>
+					</availableFormats>
+					<intervalFormats>
+						<intervalFormatFallback>↑↑↑</intervalFormatFallback>
+						<intervalFormatItem id="Bh">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="h">h – h B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Bhm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="h">h:mm – h:mm B</greatestDifference>
+							<greatestDifference id="m">h:mm – h:mm B</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="d">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="h">
+							<greatestDifference id="B">h B – h B</greatestDifference>
+							<greatestDifference id="a">h a – h a</greatestDifference>
+							<greatestDifference id="h">h – h a</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="H">
+							<greatestDifference id="H" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hm">
+							<greatestDifference id="B">h:mm B – h:mm B</greatestDifference>
+							<greatestDifference id="a">h:mm a – h:mm a</greatestDifference>
+							<greatestDifference id="h">↑↑↑</greatestDifference>
+							<greatestDifference id="m">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hm">
+							<greatestDifference id="H" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="m" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hmv">
+							<greatestDifference id="B">h:mm B – h:mm B v</greatestDifference>
+							<greatestDifference id="a">h:mm a – h:mm a v</greatestDifference>
+							<greatestDifference id="h">↑↑↑</greatestDifference>
+							<greatestDifference id="m">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hmv">
+							<greatestDifference id="H" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="m" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="hv">
+							<greatestDifference id="B">h:mm B – h:mm B v</greatestDifference>
+							<greatestDifference id="a">h a – h a v</greatestDifference>
+							<greatestDifference id="h">h – h a v</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Hv">
+							<greatestDifference id="H" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="M">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="Md">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="MMMEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="y">
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMEd">
+							<greatestDifference id="d" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+						<intervalFormatItem id="yMMMM">
+							<greatestDifference id="M" draft="contributed">↑↑↑</greatestDifference>
+							<greatestDifference id="y" draft="contributed">↑↑↑</greatestDifference>
+						</intervalFormatItem>
+					</intervalFormats>
+				</dateTimeFormats>
+			</calendar>
+		</calendars>
+	</dates>
+</ldml>
\ No newline at end of file
diff --git a/common/main/en_UA.xml b/common/main/en_UA.xml
new file mode 100644
index 00000000..6dc74027
--- /dev/null
+++ b/common/main/en_UA.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="en"/>
+		<territory type="UA"/>
+	</identity>
+	<numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group> </group>
+		</symbols>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/es_FR.xml b/common/main/es_FR.xml
new file mode 100644
index 00000000..50526fda
--- /dev/null
+++ b/common/main/es_FR.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="es"/>
+		<territory type="FR"/>
+	</identity>
+  <numbers>
+		<symbols numberSystem="latn">
+			<decimal>,</decimal>
+			<group> </group>
+		</symbols>
+	</numbers>
+</ldml>
\ No newline at end of file
diff --git a/common/main/ru_EE.xml b/common/main/ru_EE.xml
new file mode 100644
index 00000000..fe7a15d2
--- /dev/null
+++ b/common/main/ru_EE.xml
@@ -0,0 +1,14 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="ru"/>
+		<territory type="EE"/>
+	</identity>
+</ldml>
\ No newline at end of file
diff --git a/common/main/ru_LT.xml b/common/main/ru_LT.xml
new file mode 100644
index 00000000..c466b21e
--- /dev/null
+++ b/common/main/ru_LT.xml
@@ -0,0 +1,14 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="ru"/>
+		<territory type="LT"/>
+	</identity>
+</ldml>
\ No newline at end of file
diff --git a/common/main/ru_LV.xml b/common/main/ru_LV.xml
new file mode 100644
index 00000000..b2b5e48f
--- /dev/null
+++ b/common/main/ru_LV.xml
@@ -0,0 +1,14 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="ru"/>
+		<territory type="LV"/>
+	</identity>
+</ldml>
\ No newline at end of file
diff --git a/common/main/ru_PL.xml b/common/main/ru_PL.xml
new file mode 100644
index 00000000..dff63873
--- /dev/null
+++ b/common/main/ru_PL.xml
@@ -0,0 +1,14 @@
+<?xml version="1.0" encoding="UTF-8" ?>
+<!DOCTYPE ldml SYSTEM "../../common/dtd/ldml.dtd">
+<!-- Copyright © 1991-2025 Unicode, Inc.
+For terms of use, see http://www.unicode.org/copyright.html
+SPDX-License-Identifier: Unicode-3.0
+CLDR data files are interpreted according to the LDML specification (http://unicode.org/reports/tr35/)
+-->
+<ldml>
+	<identity>
+		<version number="$Revision$"/>
+		<language type="ru"/>
+		<territory type="PL"/>
+	</identity>
+</ldml>
\ No newline at end of file
diff --git a/common/supplemental/metaZones.xml b/common/supplemental/metaZones.xml
index 9a610def..c6d4f21e 100644
--- a/common/supplemental/metaZones.xml
+++ b/common/supplemental/metaZones.xml
@@ -645,6 +645,9 @@ For terms of use, see http://www.unicode.org/copyright.html
 			<timezone type="America/Punta_Arenas">
 				<usesMetazone to="2016-12-03 23:00" mzone="Chile"/>
 			</timezone>
+			<timezone type="America/Coyhaique">
+				<usesMetazone to="2025-03-19 21:00" mzone="Chile"/>
+			</timezone>
 			<timezone type="America/Rankin_Inlet">
 				<usesMetazone to="2000-10-29 07:00" mzone="America_Central"/>
 				<usesMetazone to="2001-04-01 08:00" from="2000-10-29 07:00" mzone="America_Eastern"/>
diff --git a/common/supplemental/supplementalData.xml b/common/supplemental/supplementalData.xml
index 885e6db0..50df2423 100644
--- a/common/supplemental/supplementalData.xml
+++ b/common/supplemental/supplementalData.xml
@@ -4914,7 +4914,7 @@ XXX Code for transations where no currency is involved
 		<hours preferred="H" allowed="H K h" regions="JP"/>
 		<hours preferred="H" allowed="H hb hB h" regions="AF LA"/>
 		<hours preferred="H" allowed="H hB"
-			regions="AD AM AO AT AW BE BF BJ BL BR CG CI CV CW DE EE FR GA GF GN GP GW HR IL IT KZ MC MD MF MQ MZ NC NL PM PT RE RO SI SR ST TG TR WF YT"/>
+			regions="AD AM AO AT AW BE BF BJ BL BR CG CI CV CW DE EE FR GA GF GN GP GW HR IL IT KZ MC MD MF MQ MZ NC NL PM PT RE RO SI SR ST TG TR WF YT en_CD"/>
 		<hours preferred="H" allowed="H hB h" regions="AZ BA BG CH GE LI ME RS UA UZ XK"/>
 		<hours preferred="H" allowed="H hB h hb" regions="ES GQ"/>
 		<hours preferred="H" allowed="H hB hb h" regions="CN LV TL zu_ZA"/>
@@ -4925,7 +4925,7 @@ XXX Code for transations where no currency is involved
 		<hours preferred="h" allowed="h H hB" regions="AL TD"/>
 		<hours preferred="h" allowed="h H hB hb" regions="419 AR BO CL CO CR CU DO EC GT HN KP KR MX NI NA PA PE PR PY SV UY VE"/>
 		<hours preferred="h" allowed="h hb H hB"
-			regions="AG AU BB BM BS CA DM FJ FM GD GM GU GY JM KI KN KY LC LR MH MP MW NZ SB SG SL SS SZ TC TT UM US VC VG VI ZM en_001 en_HK en_MY"/>
+			regions="AG AU BB BM BS CA DM FJ FM GD GM GU GY JM KI KN KY LC LR MH MP MW NZ SB SG SL SS SZ TC TT UM US VC VG VI ZM en_001 en_HK en_MY en_TW"/>
 		<hours preferred="h" allowed="h hB H" regions="BD PK"/>
 		<hours preferred="h" allowed="h hB hb H" regions="AE BH DZ EG EH HK IQ JO KW LB LY MO MR OM PH PS QA SA SD SY TN YE ar_001"/>
 		<hours preferred="h" allowed="hb hB h H" regions="BN MY"/>
@@ -5448,8 +5448,8 @@ XXX Code for transations where no currency is involved
 
 	<parentLocales>
 		<parentLocale parent="root" localeRules="nonlikelyScript" locales="az_Arab az_Cyrl bal_Latn blt_Latn bm_Nkoo bs_Cyrl byn_Latn cu_Glag dje_Arab dyo_Arab en_Dsrt en_Shaw ff_Adlm ff_Arab ha_Arab iu_Latn kaa_Latn kk_Arab kok_Latn ks_Deva ku_Arab kxv_Deva kxv_Orya kxv_Telu ky_Arab ky_Latn ml_Arab mn_Mong mni_Mtei ms_Arab pa_Arab sat_Deva sd_Deva sd_Khoj sd_Sind shi_Latn so_Arab sr_Latn sw_Arab tg_Arab ug_Cyrl uz_Arab uz_Cyrl vai_Latn wo_Arab yo_Arab yue_Hans zh_Hant"/>
-		<parentLocale parent="en_001" locales="en_150 en_AG en_AI en_AU en_BB en_BM en_BS en_BW en_BZ en_CC en_CK en_CM en_CX en_CY en_DG en_DM en_ER en_FJ en_FK en_FM en_GB en_GD en_GG en_GH en_GI en_GM en_GY en_HK en_ID en_IE en_IL en_IM en_IN en_IO en_JE en_JM en_KE en_KI en_KN en_KY en_LC en_LR en_LS en_MG en_MO en_MS en_MT en_MU en_MV en_MW en_MY en_NA en_NF en_NG en_NR en_NU en_NZ en_PG en_PK en_PN en_PW en_RW en_SB en_SC en_SD en_SG en_SH en_SL en_SS en_SX en_SZ en_TC en_TK en_TO en_TT en_TV en_TZ en_UG en_VC en_VG en_VU en_WS en_ZA en_ZM en_ZW"/>
-		<parentLocale parent="en_150" locales="en_AT en_BE en_CH en_CZ en_DE en_DK en_ES en_FI en_FR en_HU en_IT en_NL en_NO en_PL en_PT en_RO en_SE en_SI en_SK"/>
+		<parentLocale parent="en_001" locales="en_150 en_AG en_AI en_AU en_BB en_BD en_BM en_BS en_BW en_BZ en_CC en_CK en_CM en_CX en_CY en_DG en_DM en_ER en_FJ en_FK en_FM en_GB en_GD en_GG en_GH en_GI en_GM en_GY en_HK en_ID en_IE en_IL en_IM en_IN en_IO en_JE en_JM en_KE en_KI en_KN en_KY en_LC en_LK en_LR en_LS en_MA en_MG en_MO en_MS en_MT en_MU en_MV en_MW en_MY en_NA en_NF en_NG en_NR en_NU en_NZ en_PG en_PK en_PN en_PW en_RW en_SA en_SB en_SC en_SD en_SG en_SH en_SL en_SS en_SX en_SZ en_TC en_TK en_TO en_TT en_TV en_TZ en_UG en_VC en_VG en_VU en_WS en_ZA en_ZM en_ZW"/>
+		<parentLocale parent="en_150" locales="en_AT en_BE en_CH en_CZ en_DE en_DK en_EE en_ES en_FI en_FR en_GE en_HU en_IT en_LT en_LV en_NL en_NO en_PL en_PT en_RO en_SE en_SI en_SK en_UA"/>
 		<parentLocale parent="en_IN" locales="hi_Latn"/>
 		<parentLocale parent="es_419" locales="es_AR es_BO es_BR es_BZ es_CL es_CO es_CR es_CU es_DO es_EC es_GT es_HN es_JP es_MX es_NI es_PA es_PE es_PR es_PY es_SV es_US es_UY es_VE"/>
 		<parentLocale parent="fr_HT" locales="ht"/>
diff --git a/common/supplemental/windowsZones.xml b/common/supplemental/windowsZones.xml
index 7ec2ab61..26a62c3f 100644
--- a/common/supplemental/windowsZones.xml
+++ b/common/supplemental/windowsZones.xml
@@ -235,7 +235,7 @@ For terms of use, see http://www.unicode.org/copyright.html
 
 			<!-- (UTC-03:00) Punta Arenas -->
 			<mapZone other="Magallanes Standard Time" territory="001" type="America/Punta_Arenas"/>
-			<mapZone other="Magallanes Standard Time" territory="CL" type="America/Punta_Arenas"/>
+			<mapZone other="Magallanes Standard Time" territory="CL" type="America/Punta_Arenas America/Coyhaique"/>
 
 			<!-- (UTC-03:00) Saint Pierre and Miquelon -->
 			<mapZone other="Saint Pierre Standard Time" territory="001" type="America/Miquelon"/>
diff --git a/tools/cldr-code/src/main/java/org/unicode/cldr/test/SubmissionLocales.java b/tools/cldr-code/src/main/java/org/unicode/cldr/test/SubmissionLocales.java
index 11a8a196..3a50b1ef 100644
--- a/tools/cldr-code/src/main/java/org/unicode/cldr/test/SubmissionLocales.java
+++ b/tools/cldr-code/src/main/java/org/unicode/cldr/test/SubmissionLocales.java
@@ -130,6 +130,8 @@ public final class SubmissionLocales {
                             + "|localeDisplayNames/territories/territory\\[@type=\"TR\"\\].*"
                             // v43: Exemplar city for America/Ciudad_Juarez
                             + "|dates/timeZoneNames/zone[@type=\"America/Ciudad_Juarez\"]/exemplarCity"
+                            // v48: Exemplar city for America/Coyhaique
+                            + "|dates/timeZoneNames/zone\\[@type=\"America/Coyhaique\"]/exemplarCity"
                             + ")");
 
     // Pattern.compile("//ldml/units/unitLength\\[@type=\"long\"]");
diff --git a/tools/cldr-code/src/main/java/org/unicode/cldr/util/PathHeader.java b/tools/cldr-code/src/main/java/org/unicode/cldr/util/PathHeader.java
index fef2148f..45f04c85 100644
--- a/tools/cldr-code/src/main/java/org/unicode/cldr/util/PathHeader.java
+++ b/tools/cldr-code/src/main/java/org/unicode/cldr/util/PathHeader.java
@@ -1524,6 +1524,10 @@ public class PathHeader implements Comparable<PathHeader> {
                                     || "ZZ".equals(theTerritory)) {
                                 if ("Etc/Unknown".equals(source0)) {
                                     theTerritory = "ZZ";
+                                    // TODO (ICU-23096): remove else-if branch below once ICU's
+                                    // snapshot version is uploaded.
+                                } else if ("America/Coyhaique".equals(source0)) {
+                                    theTerritory = "CL";
                                 } else {
                                     throw new IllegalArgumentException(
                                             "ICU needs zone update? Source: "
diff --git a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/asia b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/asia
index f78a1647..b5c0da55 100644
--- a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/asia
+++ b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/asia
@@ -1500,6 +1500,16 @@ Zone Asia/Jayapura	9:22:48 -	LMT	1932 Nov
 # (UIT No. 143 17.XI.1977) and not 23 September (UIT No. 141 13.IX.1977).
 # UIT is the Operational Bulletin of International Telecommunication Union.
 
+# From Roozbeh Pournader (2025-03-18):
+# ... the exact time of Iran's transition from +0400 to +0330 ... was Friday
+# 1357/8/19 AP=1978-11-10. Here's a newspaper clip from the Ettela'at
+# newspaper, dated 1357/8/14 AP=1978-11-05, translated from Persian
+# (at https://w.wiki/DUEY):
+#	Following the government's decision about returning the official time
+#	to the previous status, the spokesperson for the Ministry of Energy
+#	announced today: At the hour 24 of Friday 19th of Aban (=1978-11-10),
+#	the country's time will be pulled back half an hour.
+#
 # From Roozbeh Pournader (2003-03-15):
 # This is an English translation of what I just found (originally in Persian).
 # The Gregorian dates in brackets are mine:
@@ -1627,7 +1637,7 @@ Rule	Iran	2021	2022	-	Sep	21	24:00	0	-
 Zone	Asia/Tehran	3:25:44	-	LMT	1916
 			3:25:44	-	TMT	1935 Jun 13 # Tehran Mean Time
 			3:30	Iran	+0330/+0430	1977 Oct 20 24:00
-			4:00	Iran	+04/+05	1979
+			4:00	Iran	+04/+05	1978 Nov 10 24:00
 			3:30	Iran	+0330/+0430
 
 
diff --git a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/northamerica b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/northamerica
index e2ca7ddf..63abbd2a 100644
--- a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/northamerica
+++ b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/northamerica
@@ -1611,6 +1611,15 @@ Zone America/Moncton	-4:19:08 -	LMT	1883 Dec  9
 # For more on Orillia, see: Daubs K. Bold attempt at daylight saving
 # time became a comic failure in Orillia. Toronto Star 2017-07-08.
 # https://www.thestar.com/news/insight/2017/07/08/bold-attempt-at-daylight-saving-time-became-a-comic-failure-in-orillia.html
+# From Paul Eggert (2025-03-20):
+# Also see the 1912-06-17 front page of The Evening Sunbeam,
+# reproduced in: Richardson M. "Daylight saving was a confusing
+# time in Orillia" in the 2025-03-15 Orillia Matters. Richardson writes,
+# "The first Sunday after the switch was made, [DST proponent and
+# Orillia mayor William Sword] Frost walked into church an hour late.
+# This became a symbol of the downfall of daylight saving in Orillia."
+# The mayor became known as "Daylight Bill".
+# https://www.orilliamatters.com/local-news/column-daylight-saving-was-a-confusing-time-in-orillia-10377529
 
 # From Mark Brader (2010-03-06):
 #
diff --git a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/southamerica b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/southamerica
index a406298e..311f21a3 100644
--- a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/southamerica
+++ b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/southamerica
@@ -1246,35 +1246,45 @@ Zone America/Rio_Branco	-4:31:12 -	LMT	1914
 # dates to 2014.
 # DST End: last Saturday of April 2014 (Sun 27 Apr 2014 03:00 UTC)
 # DST Start: first Saturday of September 2014 (Sun 07 Sep 2014 04:00 UTC)
-# http://www.diariooficial.interior.gob.cl//media/2014/02/19/do-20140219.pdf
+# From Tim Parenti (2025-03-22):
+# Decreto 307 of 2014 of the Ministry of the Interior and Public Security,
+# promulgated 2014-01-30 and published 2014-02-19:
+# https://www.diariooficial.interior.gob.cl/media/2014/02/19/do-20140219.pdf#page=1
+# https://www.bcn.cl/leychile/navegar?idNorma=1059557
 
 # From Eduardo Romero Urra (2015-03-03):
 # Today has been published officially that Chile will use the DST time
 # permanently until March 25 of 2017
-# http://www.diariooficial.interior.gob.cl/media/2015/03/03/1-large.jpg
-#
-# From Paul Eggert (2015-03-03):
-# For now, assume that the extension will persist indefinitely.
+# From Tim Parenti (2025-03-22):
+# Decreto 106 of 2015 of the Ministry of the Interior and Public Security,
+# promulgated 2015-01-27 and published 2015-03-03:
+# https://www.diariooficial.interior.gob.cl/media/2015/03/03/do-20150303.pdf#page=1
+# https://www.bcn.cl/leychile/navegar?idNorma=1075157
 
 # From Juan Correa (2016-03-18):
-# The decree regarding DST has been published in today's Official Gazette:
-# http://www.diariooficial.interior.gob.cl/versiones-anteriores/do/20160318/
-# http://www.leychile.cl/Navegar?idNorma=1088502
+# The decree regarding DST has been published in today's Official Gazette...
 # It does consider the second Saturday of May and August as the dates
 # for the transition; and it lists DST dates until 2019, but I think
 # this scheme will stick.
-#
 # From Paul Eggert (2016-03-18):
-# For now, assume the pattern holds for the indefinite future.
 # The decree says transitions occur at 24:00; in practice this appears
 # to mean 24:00 mainland time, not 24:00 local time, so that Easter
 # Island is always two hours behind the mainland.
+# From Tim Parenti (2025-03-22):
+# Decreto 253 of 2016 of the Ministry of the Interior and Public Security,
+# promulgated 2016-03-16 and published 2016-03-18.
+# https://www.diariooficial.interior.gob.cl/media/2016/03/18/do-20160318.pdf#page=1
+# https://www.bcn.cl/leychile/navegar?idNorma=1088502
 
 # From Juan Correa (2016-12-04):
 # Magallanes region ... will keep DST (UTC -3) all year round....
 # http://www.soychile.cl/Santiago/Sociedad/2016/12/04/433428/Bachelet-firmo-el-decreto-para-establecer-un-horario-unico-para-la-Region-de-Magallanes.aspx
-# From Deborah Goldsmith (2017-01-19):
-# http://www.diariooficial.interior.gob.cl/publicaciones/2017/01/17/41660/01/1169626.pdf
+# From Tim Parenti (2025-03-22), via Deborah Goldsmith (2017-01-19):
+# Decreto 1820 of 2016 of the Ministry of the Interior and Public Security,
+# promulgated 2016-12-02 and published 2017-01-17:
+# https://www.diariooficial.interior.gob.cl/publicaciones/2017/01/17/41660/01/1169626.pdf
+# https://www.bcn.cl/leychile/Navegar?idNorma=1099217
+# Model this as a change to standard offset effective 2016-12-04.
 
 # From Juan Correa (2018-08-13):
 # As of moments ago, the Ministry of Energy in Chile has announced the new
@@ -1293,13 +1303,20 @@ Zone America/Rio_Branco	-4:31:12 -	LMT	1914
 # https://twitter.com/MinEnergia/status/1029009354001973248
 # "We will keep the new time policy unchanged for at least the next 4 years."
 # So we extend the new rules on Saturdays at 24:00 mainland time indefinitely.
-# From Juan Correa (2019-02-04):
-# http://www.diariooficial.interior.gob.cl/publicaciones/2018/11/23/42212/01/1498738.pdf
+# From Tim Parenti (2025-03-22), via Juan Correa (2019-02-04):
+# Decreto 1286 of 2018 of the Ministry of the Interior and Public Security,
+# promulgated 2018-09-21 and published 2018-11-23:
+# https://www.diariooficial.interior.gob.cl/publicaciones/2018/11/23/42212/01/1498738.pdf
+# https://www.bcn.cl/leychile/Navegar?idNorma=1125760
 
 # From Juan Correa (2022-04-02):
 # I found there was a decree published last Thursday that will keep
-# Magallanes region to UTC -3 "indefinitely". The decree is available at
+# Magallanes region to UTC -3 "indefinitely".
+# From Tim Parenti (2025-03-22):
+# Decreto 143 of 2022 of the Ministry of the Interior and Public Security,
+# promulgated 2022-03-29 and published 2022-03-31:
 # https://www.diariooficial.interior.gob.cl/publicaciones/2022/03/31/43217-B/01/2108910.pdf
+# https://www.bcn.cl/leychile/Navegar?idNorma=1174342
 
 # From Juan Correa (2022-08-09):
 # the Internal Affairs Ministry (Ministerio del Interior) informed DST
@@ -1308,13 +1325,36 @@ Zone America/Rio_Branco	-4:31:12 -	LMT	1914
 # will keep UTC -3 "indefinitely"...  This is because on September 4th
 # we will have a voting whether to approve a new Constitution.
 #
-# From Eduardo Romero Urra (2022-08-17):
+# From Tim Parenti (2025-03-22), via Eduardo Romero Urra (2022-08-17):
+# Decreto 224 of 2022 of the Ministry of the Interior and Public Security,
+# promulgated 2022-07-14 and published 2022-08-13:
 # https://www.diariooficial.interior.gob.cl/publicaciones/2022/08/13/43327/01/2172567.pdf
+# https://www.bcn.cl/leychile/navegar?idNorma=1179983
 #
 # From Paul Eggert (2022-08-17):
 # Although the presidential decree stops at fall 2026, assume that
 # similar DST rules will continue thereafter.
 
+# From Paul Eggert (2025-01-15):
+# Diario Regional Aysén's Sebastián Martel reports that 94% of Aysén
+# citizens polled in November favored changing the rules from
+# -04/-03-with-DST to -03 all year...
+# https://www.diarioregionalaysen.cl/noticia/actualidad/2024/12/presentan-decision-que-gano-la-votacion-sobre-el-cambio-del-huso-horario-en-aysen
+#
+# From Yonathan Dossow (2025-03-20):
+# [T]oday we have more confirmation of the change.  [Aysén] region will keep
+# UTC-3 all year...
+# https://www.cnnchile.com/pais/region-de-aysen-mantendra-horario-de-verano-todo-el-ano_20250320/
+# https://www.latercera.com/nacional/noticia/tras-consulta-ciudadana-region-de-aysen-mantendra-el-horario-de-verano-durante-todo-el-ano/
+# https://x.com/min_interior/status/1902692504270672098
+#
+# From Tim Parenti (2025-03-22), via Eduardo Romero Urra (2025-03-20):
+# Decreto 93 of 2025 of the Ministry of the Interior and Public Security,
+# promulgated 2025-03-11 and published 2025-03-20:
+# https://www.diariooficial.interior.gob.cl/publicaciones/2025/03/20/44104/01/2624263.pdf
+# https://www.bcn.cl/leychile/Navegar?idNorma=1211955
+# Model this as a change to standard offset effective 2025-03-20.
+
 # Rule	NAME	FROM	TO	-	IN	ON	AT	SAVE	LETTER/S
 Rule	Chile	1927	1931	-	Sep	 1	0:00	1:00	-
 Rule	Chile	1928	1932	-	Apr	 1	0:00	0	-
@@ -1371,6 +1411,20 @@ Zone America/Santiago	-4:42:45 -	LMT	1890
 			-5:00	1:00	-04	1947 Mar 31 24:00
 			-5:00	-	-05	1947 May 21 23:00
 			-4:00	Chile	-04/-03
+Zone America/Coyhaique	-4:48:16 -	LMT	1890
+			-4:42:45 -	SMT	1910 Jan 10
+			-5:00	-	-05	1916 Jul  1
+			-4:42:45 -	SMT	1918 Sep 10
+			-4:00	-	-04	1919 Jul  1
+			-4:42:45 -	SMT	1927 Sep  1
+			-5:00	Chile	-05/-04	1932 Sep  1
+			-4:00	-	-04	1942 Jun  1
+			-5:00	-	-05	1942 Aug  1
+			-4:00	-	-04	1946 Aug 28 24:00
+			-5:00	1:00	-04	1947 Mar 31 24:00
+			-5:00	-	-05	1947 May 21 23:00
+			-4:00	Chile	-04/-03	2025 Mar 20
+			-3:00	-	-03
 Zone America/Punta_Arenas -4:43:40 -	LMT	1890
 			-4:42:45 -	SMT	1910 Jan 10
 			-5:00	-	-05	1916 Jul  1
diff --git a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/tzdb-version.txt b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/tzdb-version.txt
index 0846b7f2..ef468adc 100644
--- a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/tzdb-version.txt
+++ b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/tzdb-version.txt
@@ -1 +1 @@
-2025a
+2025b
diff --git a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/zone.tab b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/zone.tab
index d2be6635..2626b055 100644
--- a/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/zone.tab
+++ b/tools/cldr-code/src/main/resources/org/unicode/cldr/util/data/zone.tab
@@ -139,7 +139,8 @@ CH	+4723+00832	Europe/Zurich
 CI	+0519-00402	Africa/Abidjan
 CK	-2114-15946	Pacific/Rarotonga
 CL	-3327-07040	America/Santiago	most of Chile
-CL	-5309-07055	America/Punta_Arenas	Region of Magallanes
+CL	-4534-07204	America/Coyhaique	Aysen Region
+CL	-5309-07055	America/Punta_Arenas	Magallanes Region
 CL	-2709-10926	Pacific/Easter	Easter Island
 CM	+0403+00942	Africa/Douala
 CN	+3114+12128	Asia/Shanghai	Beijing Time
diff --git a/tools/cldr-code/src/test/java/org/unicode/cldr/unittest/TestBCP47.java b/tools/cldr-code/src/test/java/org/unicode/cldr/unittest/TestBCP47.java
index 01af7fd0..f15a2ae0 100644
--- a/tools/cldr-code/src/test/java/org/unicode/cldr/unittest/TestBCP47.java
+++ b/tools/cldr-code/src/test/java/org/unicode/cldr/unittest/TestBCP47.java
@@ -337,6 +337,8 @@ public class TestBCP47 extends TestFmwk {
                     "WET");
 
     public void testBcp47IdsForAllTimezoneIds() {
+        // TODO (ICU-23096): remove once ICU is updated.
+        Set<String> newlyIntroducedTimeZoneIds = Set.of("clcxq");
         Map<String, String> aliasToId = new TreeMap<>();
         Set<String> missingAliases = new TreeSet<>();
         Set<String> deprecatedAliases = new TreeSet<>();
@@ -349,7 +351,9 @@ public class TestBCP47 extends TestFmwk {
             if (itemIsDeprecated) {
                 deprecatedBcp47s.add(bcp47Type);
             }
-            bcp47IdsNotUsed.add(bcp47Type);
+            if (!newlyIntroducedTimeZoneIds.contains(bcp47Type)) {
+                bcp47IdsNotUsed.add(bcp47Type);
+            }
             if (aliasSet == null) {
                 continue;
             }
```

