package printer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"time"
)

const urlCertImport = "/net/security/certificate/import.html"

// UploadNewCert converts the specified pem files into p12 format and installs them
// on the printer. It returns the id value of the newly installed cert.
func (p *printer) UploadNewCert(keyPem, certPem []byte) (string, error) {
	// make p12 from key and cert pem
	p12, err := makeModernPfx(keyPem, certPem, "")
	if err != nil {
		return "", fmt.Errorf("printer: failed to make p12 file (%w)", err)
	}

	// GET current cert IDs
	origCertIDs, err := p.getCertIDs()
	if err != nil {
		return "", err
	}

	// GET import page to obtain CSRFToken
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return "", err
	}
	u.Path = urlCertImport

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("printer: get of certificate import page failed (status code %d)", resp.StatusCode)
	}

	// find CSRFToken
	csrfToken, err := parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return "", err
	}

	// make writer for multipart/form-data submission
	var formDataBuffer bytes.Buffer
	formWriter := multipart.NewWriter(&formDataBuffer)

	// make form fields
	err = formWriter.WriteField("pageid", "490")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("CSRFToken", csrfToken)
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("B1179", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("B1187", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("hidden_certificate_process_control", "1")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	p12W, err := formWriter.CreateFormFile("B1063", "certkey.p12")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	_, err = io.Copy(p12W, bytes.NewReader(p12))
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("B1064", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("hidden_cert_import_password", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.Close()
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to close form (%w)", err)
	}

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return "", err
	}
	u.Path = urlCertImport

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), &formDataBuffer)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", formWriter.FormDataContentType())

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// read body of response
	_, _ = io.Copy(io.Discard, resp.Body)

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("printer: post of new certificate failed (status code %d)", resp.StatusCode)
	}

	// normally the webUI would show a waiting screen for ~7 seconds. insert
	// a delay here to account for any processing the device might do
	// before next steps
	time.Sleep(10 * time.Second)

	// get new cert ID list
	newCertIDs, err := p.getCertIDs()
	if err != nil {
		return "", err
	}

	// find ID that is in new list but not in old (this is the new one)
	newId := ""
	countNew := 0
	for i := range newCertIDs {
		found := slices.Contains(origCertIDs, newCertIDs[i])

		if !found {
			newId = newCertIDs[i]
			countNew++
		}
	}

	if countNew == 0 {
		return "", errors.New("printer: upload: didn't find new cert in list")
	}
	// if more than one new, can't determine which was uploaded by this app
	if countNew > 1 {
		return "", errors.New("printer: upload: failed to deduce new cert's id")
	}

	return newId, nil
}
