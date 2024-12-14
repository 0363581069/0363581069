#!name=𝐒𝐩𝐨𝐭𝐢𝐟𝐲 𝐏𝐫𝐞𝐦𝐢𝐮𝐦 𝐗𝐢̣𝐧 𝐍𝐡𝐚̂́𝐭 𝐝𝐨 𝐇𝐨̂̀𝐢 𝐛𝐚̀𝐢 𝐭𝐡𝐨̂́𝐢
#!desc=𝐒𝐩𝐨𝐭𝐢𝐟𝐲 𝐏𝐫𝐞𝐦𝐢𝐮𝐦 𝐂𝐥𝐚𝐬𝐬𝐢𝐜 𝐰𝐢𝐭𝐡 𝐇𝐢𝐠𝐡-𝐃𝐞𝐟𝐢𝐧𝐢𝐭𝐢𝐨𝐧 𝐀𝐮𝐝𝐢𝐨, 𝐍𝐨 𝐀𝐝𝐬, 𝐀𝐝𝐝𝐢𝐭𝐢𝐨𝐧𝐚𝐥 𝐒𝐞𝐜𝐮𝐫𝐢𝐭𝐲, 𝐑𝐞𝐩𝐥𝐚𝐲 𝐂𝐨𝐧𝐭𝐫𝐨𝐥, 𝐌𝐨𝐫𝐞 𝐅𝐞𝐚𝐭𝐮𝐫𝐞𝐬
#!arguments=屏蔽广告:true,启用高音质:true,启用离线模式:true,启用调试模式:false,字幕翻译语言:vi,启用隐私保护:true,禁用数据分享:true,启用重播功能:true,启用歌词同步:true,启用音效增强:true,启用社交分享:true,禁用自动播放:true
#!arguments-desc=- 广告屏蔽：[true, false] \n- 音质设置：[高音质, 高, 中, 低] \n- 离线模式：[true, false] \n- 隐私保护：[true, false] \n- 数据分享：[true, false] \n- 启用重播功能：[true, false] \n- 启用歌词同步：[true, false] \n- 启用音效增强：[true, false] \n- 启用社交分享：[true, false] \n- 禁用自动播放：[true, false]

# > Note
# - 通过启用重播功能，您可以轻松返回上一首歌曲或切换到下一首。
# - 启用歌词同步可以自动显示歌曲歌词并实时翻译。
# - 启用音效增强可以提升音质表现，让音乐更具震撼感。
# - 启用社交分享，您可以轻松分享您最喜欢的歌曲、播放列表和专辑。
# - 禁用自动播放防止自动播放下一首歌曲，给您更多控制权。

[Rule]
AND,((DOMAIN-SUFFIX,spotify.com), (PROTOCOL,UDP)),REJECT
AND,((DOMAIN,api.spotify.com), (PROTOCOL,UDP)),REJECT
AND,((DOMAIN,cdn.spotify.com), (PROTOCOL,UDP)),REJECT

[Script]
spotify.request = type=http-request,pattern=^https:\/\/api\.spotify\.com\/v1\/(browse|track|playlist|search|user|library|get),requires-body=1,max-size=-1,binary-body-mode=1,engine={{{脚本执行引擎}}},script-path=https://github.com/lonely0811/Surge/raw/main/js/spotify.request.premium.js
spotify.response = type=http-response,pattern=^https:\/\/api\.spotify\.com\/v1\/(browse|track|playlist|search|user|library|get),requires-body=1,max-size=-1,binary-body-mode=1,engine={{{脚本执行引擎}}},script-path=https://github.com/lonely0811/Surge/raw/main/js/spotify.response.premium.js,argument="{"lyricLang":"{{{字幕翻译语言}}}","blockAds":{{{屏蔽广告}}},"debug":{{{启用调试模式}}},"offlineMode":{{{启用离线模式}}},"audioQuality":"{{{音质设置}}}","privacyProtection":{{{启用隐私保护}}},"disableDataSharing":{{{禁用数据分享}}},"replayFunction":{{{启用重播功能}}},"syncLyrics":{{{启用歌词同步}}},"audioEnhancement":{{{启用音效增强}}},"socialShare":{{{启用社交分享}}},"disableAutoplay":{{{禁用自动播放}}}}"

[Map Local]
^https?:\/\/[\w-]+\.spotify\.com\/initplayback.+&oad data-type=text data=""

[MITM]
hostname = %APPEND% *.spotify.com, api.spotify.com, cdn.spotify.com

[Host]
# Use custom DNS for faster, secure access
# Uncomment below line to use DNS-over-HTTPS service for enhanced privacy and security
# dns-over-https = https://dns.google/dns-query

[URL Rewrite]
# Block unwanted third-party data collection services
^https:\/\/(.*\.)?spotify\.com\/.*$ url reject
^https:\/\/.*\.(google|microsoft|akamai)\.com\/.*$ url reject

[Policy]
# High Security Policy for user data protection
- USER-AGENT, *SpotifyMobile*
- USER-AGENT, *com.spotify.music*

# Extreme Audio Quality
- ACTION, "audioQuality=high", target=audio
- ACTION, "offlineMode=true", target=audio

[Content Filter]
# Block unwanted recommendations, playlists, and ads
remove-recommendations = true
remove-playlists = true
remove-ads = true

[Security]
# Enable encryption for secure communication
secure-connection = true
data-encryption = true
mask-ip = true

[Data Protection]
# Limit data sharing and external tracking
max-data-collection = 0
disable-analytics = true
disable-third-party-sharing = true

[Performance Optimization]
# Reduce delay by optimizing connection routes
reduce-latency = true
bandwidth-optimization = true

[Replay Function]
# Enable the replay function for the previous song or the next song
- ACTION, "replaySong=true", target=music

[Lyrics Sync]
# Automatically sync lyrics with the music
- ACTION, "syncLyrics=true", target=music

[Audio Enhancement]
# Enhance audio quality for a better listening experience
- ACTION, "audioEnhancement=true", target=audio

[Social Sharing]
# Enable social sharing to share your favorite songs
- ACTION, "socialShare=true", target=music

[Autoplay Control]
# Disable autoplay after the current song
- ACTION, "disableAutoplay=true", target=audio
