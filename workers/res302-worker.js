// CORS 유틸리티 함수
function corsHeaders() {
	return {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		'Access-Control-Max-Age': '86400'
	};
}

// JSON 응답 유틸리티 함수
function jsonResponse(obj, status = 200, extraHeaders = {}) {
	const headers = Object.assign({}, corsHeaders(), {'Content-Type':'application/json'}, extraHeaders);
	return new Response(JSON.stringify(obj), {status, headers});
}

export async function handleRequest(request, env){

	// OPTIONS preflight 처리 추가
	if(request.method === 'OPTIONS'){
		return new Response(null, {status:204, headers: corsHeaders()});
	}

	const url = new URL(request.url);
	const pathname = url.pathname;

	// 추가: POST /api/member 라우트
	if (request.method === 'POST' && pathname === '/api/member') {
		return handleAuthCallback(request, env);
	}

	// API: POST /api/shorten
	if(request.method === 'POST' && pathname === '/api/shorten'){
		return handleShorten(request, env);
	}
	// API: GET /api/list
	// if(request.method === 'GET' && pathname === '/api/list'){
	// 	return handleList(env);
	// }
	// 리다이렉트: GET /{code} 또는 /{uniqueUserId}/{code}
	if(request.method === 'GET' && pathname.length > 1){
		const fullPath = pathname.slice(1); // 예: "user123abcde/my/custom/code" 또는 "abc123"
		const pathSegments = fullPath.split('/');
		let targetCode = null; // KV에서 조회할 최종 키

		// 변경: 첫 번째 세그먼트가 uniqueUserId (영숫자)처럼 보이는지 확인하는 휴리스틱
		// makeUniqueId 함수는 12자리 ID를 생성하지만, 기존 ID나 수동 입력 ID를 위해 길이에 대한 엄격한 검사를 완화합니다.
		// 대신, 첫 번째 세그먼트가 영숫자로만 구성되어 있고, 경로 세그먼트가 2개 이상인 경우를 uniqueUserId 패턴으로 간주합니다.
		const isFirstSegmentPotentiallyUniqueUserId = pathSegments.length >= 2 && /^[a-z0-9]+$/i.test(pathSegments[0]);

		if (isFirstSegmentPotentiallyUniqueUserId) {
			// /{uniqueUserId}/{alias_with_slashes} 패턴으로 간주
			// KV 키는 전체 경로 (예: "user123abcde/my/custom/code")
			targetCode = fullPath;
		} else if (pathSegments.length === 1) {
			// /{code} 패턴 (무작위 코드)으로 간주
			targetCode = fullPath;
		}
		// 그 외의 경우 (예: pathSegments.length > 1 이지만 첫 세그먼트가 uniqueUserId 패턴이 아닌 경우)
		// 유효하지 않은 경로로 간주하여 404로 처리됩니다.

		if (targetCode) {
			const target = await env.RES302_KV.get(targetCode);
			if(target){
				return new Response(null, {status:302, headers: Object.assign({Location: target}, corsHeaders())});
			}
		}
		return new Response('Not found', {status:404, headers: corsHeaders()});
	}
	// 기타
	return new Response('Not found', {status:404, headers: corsHeaders()});
}

export default {
	fetch: handleRequest
};
