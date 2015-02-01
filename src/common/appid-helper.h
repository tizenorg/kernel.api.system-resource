/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
*/


#define PKGNAME_SIZE MAX_NAME_SIZE

/**
 * Get package name from appid.
 *	For base (rpm) packages it's the same name as appid,
 *	For SDK (tpk) packages it's 10 alpha digit before first .(dot)
 *	@param appid - given appid
 *	@param pkgname - out package name
 *	@pkgname_size - size of pkgname given buffer
 **/
void extract_pkgname(const char *appid, char *pkgname, const int pkgname_size);
